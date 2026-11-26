package dev.local.androidmirror.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface

/** Finds the address a Mac on the same LAN can reach this phone at. */
object NetworkInfo {
    /**
     * Site-local IPv4 of the Wi-Fi (or Ethernet) network, else of any up non-cellular, non-VPN
     * interface (covers hotspot/tethering; see [pickLanAddress]), else null. Scans interfaces: not on the main thread.
     */
    fun lanIpv4(context: Context): String? = fromActiveNetwork(context) ?: fromInterfaces()

    private fun fromActiveNetwork(context: Context): String? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null
        // A VPN is the active network then: the interface scan finds the Wi-Fi address under it.
        if (!isLanNetwork(caps::hasTransport)) return null
        return cm.getLinkProperties(network)?.linkAddresses
            ?.map { it.address }
            ?.firstOrNull { it is Inet4Address && it.isSiteLocalAddress }
            ?.hostAddress
    }

    private fun fromInterfaces(): String? = runCatching {
        pickLanAddress(
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp && !it.isLoopback && !it.isVirtual }
                .flatMap { i -> i.inetAddresses.toList().map { i.name to it } },
        )
    }.getOrNull()
}

/**
 * Cellular data interfaces (Qualcomm rmnet, MediaTek ccmni, Spreadtrum/Unisoc seth_ and sipa_,
 * older pdp), Wi-Fi calling's ePDG tunnels (epdg), the 464XLAT and IPv4
 * shims that ride on them (clat, v4-), dummy, and VPN tunnels (VpnService tun, platform IKEv2
 * ipsec, legacy ppp, kernel WireGuard wg). Each can hold a private 10.x address no Mac on the
 * LAN can reach: it must not be shown as the address to connect to.
 *
 * A denylist, not an allowlist: hotspot and tethering interface names are set per device
 * (ap, swlan, softap, rndis, ncm, bt-pan, p2p-…), and an allowlist missing one would hide a
 * reachable address; the cellular and VPN names come from a few fixed sources.
 */
private val NON_LAN_PREFIXES = listOf("rmnet", "ccmni", "seth_", "sipa_", "pdp", "epdg", "clat", "v4-", "dummy", "tun", "ipsec", "ppp", "wg")

/**
 * The site-local IPv4 a Mac on the LAN can reach, from (interface name, address) pairs in
 * interface order: Wi-Fi / hotspot first (wlan, ap, swlan), never a cellular or VPN one; null if none.
 */
internal fun pickLanAddress(ifaces: List<Pair<String, InetAddress>>): String? = ifaces
    .filter { (name, addr) -> addr is Inet4Address && addr.isSiteLocalAddress && NON_LAN_PREFIXES.none { name.startsWith(it) } }
    .sortedBy { (name, _) -> if (name.startsWith("wlan") || name.startsWith("ap") || name.startsWith("swlan")) 0 else 1 }
    .firstOrNull()
    ?.second
    ?.hostAddress

/**
 * A Wi-Fi or Ethernet network that is not a VPN: a VPN reports the transports it runs over
 * (Wi-Fi too), but its address is the tunnel's, which no Mac on the LAN can reach.
 */
internal fun isLanNetwork(hasTransport: (Int) -> Boolean): Boolean =
    !hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
        (hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
