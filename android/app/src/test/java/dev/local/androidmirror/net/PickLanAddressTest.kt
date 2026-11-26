package dev.local.androidmirror.net

import android.net.NetworkCapabilities.TRANSPORT_CELLULAR
import android.net.NetworkCapabilities.TRANSPORT_ETHERNET
import android.net.NetworkCapabilities.TRANSPORT_VPN
import android.net.NetworkCapabilities.TRANSPORT_WIFI
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class PickLanAddressTest {
    private fun ip(s: String) = InetAddress.getByName(s)

    @Test fun mobileDataAloneIsNoLanAddress() {
        for (name in listOf("rmnet_data0", "rmnet0", "ccmni0", "seth_lte0", "sipa_eth0", "pdp0", "epdg1", "clat4", "v4-rmnet_data0", "dummy0")) {
            assertNull(name, pickLanAddress(listOf(name to ip("10.12.34.56"))))
        }
    }

    @Test fun wifiWinsOverCellularListedFirst() =
        assertEquals("192.168.1.20", pickLanAddress(listOf("rmnet_data0" to ip("10.1.2.3"), "wlan0" to ip("192.168.1.20"))))

    @Test fun hotspotAndEthernetCount() {
        assertEquals("192.168.43.1", pickLanAddress(listOf("ap0" to ip("192.168.43.1"))))
        assertEquals("192.168.49.1", pickLanAddress(listOf("swlan0" to ip("192.168.49.1"))))
        assertEquals("10.0.0.5", pickLanAddress(listOf("eth0" to ip("10.0.0.5"))))
    }

    @Test fun wifiIsPreferredOverOtherLanInterfaces() =
        assertEquals("192.168.1.20", pickLanAddress(listOf("eth0" to ip("10.0.0.5"), "wlan0" to ip("192.168.1.20"))))

    @Test fun onlySiteLocalIpv4() {
        assertNull(pickLanAddress(listOf("wlan0" to ip("8.8.8.8"))))
        assertNull(pickLanAddress(listOf("wlan0" to ip("fe80::1"))))
        assertNull(pickLanAddress(emptyList()))
    }

    @Test fun vpnInterfacesAreNoLanAddress() {
        for (name in listOf("tun0", "ppp0", "ipsec1", "wg0")) {
            assertNull(name, pickLanAddress(listOf(name to ip("10.8.0.2"))))
        }
    }

    @Test fun wifiWinsOverAVpnListedFirst() =
        assertEquals("192.168.1.20", pickLanAddress(listOf("tun0" to ip("10.8.0.2"), "wlan0" to ip("192.168.1.20"))))
}

class IsLanNetworkTest {
    private fun lan(vararg transports: Int) = isLanNetwork { it in transports }

    @Test fun wifiAndEthernetAreLan() {
        assertTrue(lan(TRANSPORT_WIFI))
        assertTrue(lan(TRANSPORT_ETHERNET))
    }

    @Test fun cellularIsNot() = assertFalse(lan(TRANSPORT_CELLULAR))

    /** A VPN over Wi-Fi also reports TRANSPORT_WIFI; its address is the tunnel's, not the LAN's. */
    @Test fun aVpnOverWifiIsNot() = assertFalse(lan(TRANSPORT_VPN, TRANSPORT_WIFI))
}
