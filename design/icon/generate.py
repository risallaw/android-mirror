#!/usr/bin/env python3
"""Android Mirror icon generator.

Geometry is defined once (1024-unit glyph space) and emitted as:
  - master.svg (full macOS-style icon)
  - PNG previews / iconset PNGs (PIL, 4096px supersample + LANCZOS)
  - Android vector drawables (adaptive fg/bg/mono, notification icon)

Usage: generate.py [--svg FILE] [--iconset DIR] [--previews DIR] [--android RES_DIR]
(master.svg next to this script is always rewritten unless --svg points elsewhere.)
"""
import argparse, math, os
from functools import lru_cache
from PIL import Image, ImageDraw, ImageFilter, ImageChops

NAVY1, NAVY2 = (15, 27, 61), (30, 58, 138)   # #0F1B3D -> #1E3A8A
TEAL, WHITE = (45, 212, 191), (255, 255, 255)
hexc = lambda c: "#%02X%02X%02X" % c

# ---- glyph geometry (1024 space, stroke centerlines) ----
MON = (150, 200, 874, 700, 70)          # x0,y0,x1,y1,corner radius
MON_S = 60                              # monitor stroke
GAP = (225, 465)                        # monitor bottom edge is open between x=225..465 (phone halo)
PHONE = (230, 380, 460, 820, 60)        # x0,y0,x1,y1,r
PHONE_S = 60
ARC_C = (522, 450)
ARC_R = (95, 185, 275)
ARC_A = 32                              # half sweep, degrees
ARC_S = 50
GLYPH_CENTER = (512, 510)

def monitor_path():
    x0, y0, x1, y1, r = MON
    return (f"M{GAP[1]},{y1} H{x1-r} A{r},{r} 0 0 0 {x1},{y1-r} V{y0+r} A{r},{r} 0 0 0 {x1-r},{y0} "
            f"H{x0+r} A{r},{r} 0 0 0 {x0},{y0+r} V{y1-r} A{r},{r} 0 0 0 {x0+r},{y1} H{GAP[0]}")

def rrect_path(x0, y0, x1, y1, r):
    return (f"M{x0+r},{y0} H{x1-r} A{r},{r} 0 0 1 {x1},{y0+r} V{y1-r} A{r},{r} 0 0 1 {x1-r},{y1} "
            f"H{x0+r} A{r},{r} 0 0 1 {x0},{y1-r} V{y0+r} A{r},{r} 0 0 1 {x0+r},{y0} Z")

def arc_pts(R):
    cx, cy = ARC_C
    a = math.radians(ARC_A)
    return (cx + R*math.cos(-a), cy + R*math.sin(-a)), (cx + R*math.cos(a), cy + R*math.sin(a))

def arc_path(R):
    (sx, sy), (ex, ey) = arc_pts(R)
    return f"M{sx:.1f},{sy:.1f} A{R},{R} 0 0 1 {ex:.1f},{ey:.1f}"

# ---- PIL rendering of glyph into masks ----
def glyph_layers(size, scale, center=(512, 512), mono=False):
    """Returns RGBA layer with the glyph. glyph space -> px via scale (px per unit) around GLYPH_CENTER."""
    cx, cy = GLYPH_CENTER
    tx = lambda x: (x - cx) * scale + center[0]
    ty = lambda y: (y - cy) * scale + center[1]
    def box(x0, y0, x1, y1, pad=0):
        return [tx(x0 - pad), ty(y0 - pad), tx(x1 + pad), ty(y1 + pad)]
    def mask(): return Image.new("L", (size, size), 0)

    # monitor (white)
    m = mask(); d = ImageDraw.Draw(m)
    x0, y0, x1, y1, r = MON; h = MON_S / 2
    d.rounded_rectangle(box(x0, y0, x1, y1, h), radius=(r + h) * scale, outline=255, width=round(MON_S * scale))
    d.rectangle(box(GAP[0], y1 - h - 2, GAP[1], y1 + h + 2), fill=0)
    # phone body
    px0, py0, px1, py1, pr = PHONE; ph = PHONE_S / 2
    phone_outer = mask(); ImageDraw.Draw(phone_outer).rounded_rectangle(box(px0, py0, px1, py1, ph), radius=(pr + ph) * scale, fill=255)
    phone_inner = mask(); ImageDraw.Draw(phone_inner).rounded_rectangle(box(px0, py0, px1, py1, -ph), radius=max(1, (pr - ph) * scale), fill=255)
    # arcs
    a = mask(); da = ImageDraw.Draw(a)
    for R in ARC_R:
        bb = [tx(ARC_C[0] - R - ARC_S/2), ty(ARC_C[1] - R - ARC_S/2), tx(ARC_C[0] + R + ARC_S/2), ty(ARC_C[1] + R + ARC_S/2)]
        da.arc(bb, -ARC_A, ARC_A, fill=255, width=round(ARC_S * scale))
        for p in arc_pts(R):
            rr = ARC_S / 2 * scale
            da.ellipse([tx(p[0]) - rr, ty(p[1]) - rr, tx(p[0]) + rr, ty(p[1]) + rr], fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    if mono:
        sil = ImageChops.lighter(ImageChops.lighter(m, phone_outer), a)
        out.paste(Image.new("RGBA", (size, size), WHITE + (255,)), mask=sil)
        return out
    out.paste(Image.new("RGBA", (size, size), WHITE + (255,)), mask=m)
    out.paste(Image.new("RGBA", (size, size), WHITE + (255,)), mask=phone_outer)
    out.paste(Image.new("RGBA", (size, size), TEAL + (255,)), mask=phone_inner)
    out.paste(Image.new("RGBA", (size, size), TEAL + (255,)), mask=a)
    return out

def gradient(size):
    # diagonal NAVY1 (top-left) -> NAVY2 (bottom-right)
    g = Image.linear_gradient("L").rotate(0)  # vertical 256x256
    g = g.resize((size, size), Image.BILINEAR)
    gd = Image.linear_gradient("L").rotate(90).resize((size, size), Image.BILINEAR)  # horizontal
    t = ImageChops.add(g, gd, scale=2)
    return Image.composite(Image.new("RGB", (size, size), NAVY2), Image.new("RGB", (size, size), NAVY1), t)

# ---- squircle ----
SQ_N = 5.0
def squircle_pts(cx, cy, half, n=SQ_N, steps=360):
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        c, s = math.cos(t), math.sin(t)
        pts.append((cx + half * math.copysign(abs(c) ** (2 / n), c), cy + half * math.copysign(abs(s) ** (2 / n), s)))
    return pts

BODY = 824; GLYPH_SCALE_MAC = 0.86

@lru_cache(maxsize=None)
def render_master(out_size):
    S = 4096
    k = S / 1024
    body = Image.new("L", (S, S), 0)
    ImageDraw.Draw(body).polygon([(x * k, y * k) for x, y in squircle_pts(512, 512, BODY / 2)], fill=255)
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # shadow
    sh = Image.new("L", (S, S), 0)
    sh.paste(body.transform((S, S), Image.AFFINE, (1, 0, 0, 0, 1, -10 * k)))
    sh = sh.filter(ImageFilter.GaussianBlur(14 * k)).point(lambda v: int(v * 0.45))
    img.paste(Image.new("RGBA", (S, S), (0, 0, 20, 255)), mask=sh)
    bg = gradient(S).convert("RGBA")
    img.paste(bg, mask=body)
    # glyph confined to body
    g = glyph_layers(S, GLYPH_SCALE_MAC * k, center=(512 * k, 512 * k))
    img.alpha_composite(g)
    return img.resize((out_size, out_size), Image.LANCZOS)

def master_svg():
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in squircle_pts(512, 512, BODY / 2))
    s = GLYPH_SCALE_MAC; cx, cy = GLYPH_CENTER
    tr = f"translate(512 512) scale({s}) translate({-cx} {-cy})"
    arcs = "".join(f'<path d="{arc_path(R)}"/>' for R in ARC_R)
    px0, py0, px1, py1, pr = PHONE
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{hexc(NAVY1)}"/><stop offset="1" stop-color="{hexc(NAVY2)}"/></linearGradient>
    <filter id="sh" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="14"/></filter>
  </defs>
  <polygon points="{pts}" transform="translate(0 10)" fill="#000014" fill-opacity="0.45" filter="url(#sh)"/>
  <polygon points="{pts}" fill="url(#bg)"/>
  <g transform="{tr}" fill="none" stroke-linecap="round">
    <path d="{monitor_path()}" stroke="#FFFFFF" stroke-width="{MON_S}" stroke-linecap="butt"/>
    <path d="{rrect_path(px0, py0, px1, py1, pr)}" stroke="#FFFFFF" stroke-width="{PHONE_S}" fill="{hexc(TEAL)}"/>
    <g stroke="{hexc(TEAL)}" stroke-width="{ARC_S}">{arcs}</g>
  </g>
</svg>
'''

# ---- Android vectors ----
def vec_paths(fill_phone_color, stroke_color, arc_color, mono=False):
    px0, py0, px1, py1, pr = PHONE
    ph = f'''    <path
        android:pathData="{rrect_path(px0, py0, px1, py1, pr)}"
        android:fillColor="{fill_phone_color}"
        android:strokeColor="{stroke_color}"
        android:strokeWidth="{PHONE_S}"/>
'''
    mon = f'''    <path
        android:pathData="{monitor_path()}"
        android:strokeColor="{stroke_color}"
        android:strokeWidth="{MON_S}"
        android:strokeLineCap="butt"/>
'''
    arcs = "".join(f'''    <path
        android:pathData="{arc_path(R)}"
        android:strokeColor="{arc_color}"
        android:strokeWidth="{ARC_S}"
        android:strokeLineCap="round"/>
''' for R in ARC_R)
    return mon + ph + arcs

def vec_glyph(name_dp, viewport, scale, center, fp, sc, ac):
    cx, cy = GLYPH_CENTER
    tx, ty = center[0] - cx * scale, center[1] - cy * scale
    return f'''<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="{name_dp}dp"
    android:height="{name_dp}dp"
    android:viewportWidth="{viewport}"
    android:viewportHeight="{viewport}">
  <group
      android:translateX="{tx:.3f}"
      android:translateY="{ty:.3f}"
      android:scaleX="{scale}"
      android:scaleY="{scale}">
{vec_paths(fp, sc, ac)}  </group>
</vector>
'''

ADAPT_SCALE = 0.066   # 108dp canvas; glyph ~ 50dp wide, inside 66dp safe circle
NOTIF_SCALE = 0.029  # 24dp

def write_android(res):
    d = os.path.join(res, "drawable"); m = os.path.join(res, "mipmap-anydpi-v26")
    os.makedirs(d, exist_ok=True); os.makedirs(m, exist_ok=True)
    def w(p, s):
        with open(p, "w", encoding="utf-8") as f:
            f.write(s)
    w(f"{d}/ic_launcher_foreground.xml", vec_glyph(108, 108, ADAPT_SCALE, (54, 54), hexc(TEAL), "#FFFFFF", hexc(TEAL)))
    w(f"{d}/ic_launcher_monochrome.xml", vec_glyph(108, 108, ADAPT_SCALE, (54, 54), "#FFFFFF", "#FFFFFF", "#FFFFFF"))
    w(f"{d}/ic_stat_mirror.xml", vec_glyph(24, 24, NOTIF_SCALE, (12, 12), "#FFFFFF", "#FFFFFF", "#FFFFFF"))
    w(f"{d}/ic_launcher_background.xml", f'''<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:aapt="http://schemas.android.com/aapt"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
  <path android:pathData="M0,0H108V108H0Z">
    <aapt:attr name="android:fillColor">
      <gradient
          android:type="linear"
          android:startX="0"
          android:startY="0"
          android:endX="108"
          android:endY="108">
        <item android:offset="0" android:color="{hexc(NAVY1)}"/>
        <item android:offset="1" android:color="{hexc(NAVY2)}"/>
      </gradient>
    </aapt:attr>
  </path>
</vector>
''')
    ad = '''<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@drawable/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />
</adaptive-icon>
'''
    w(f"{m}/ic_launcher.xml", ad); w(f"{m}/ic_launcher_round.xml", ad)

# ---- Android previews (PIL mirror of the vectors) ----
def adaptive_preview(size, shape, mono=False):
    S = size * 4; sc = S / 108
    if mono:
        bgim = Image.new("RGBA", (S, S), (210, 225, 255, 255)); fg = glyph_layers(S, ADAPT_SCALE * sc, (S/2, S/2), mono=True)
        tint = Image.new("RGBA", (S, S), (20, 40, 100, 255)); fgm = Image.new("RGBA", (S, S), (0, 0, 0, 0)); fgm.paste(tint, mask=fg.split()[3]); fg = fgm
    else:
        bgim = gradient(S).convert("RGBA"); fg = glyph_layers(S, ADAPT_SCALE * sc, (S/2, S/2))
    bgim.alpha_composite(fg)
    mk = Image.new("L", (S, S), 0); dd = ImageDraw.Draw(mk)
    if shape == "circle": dd.ellipse([S*0.09, S*0.09, S*0.91, S*0.91], fill=255)   # 72dp visible mask region
    else: dd.polygon([(x*S/1024, y*S/1024) for x, y in squircle_pts(512, 512, 512*72/108*1.0, steps=240)], fill=255)
    o = Image.new("RGBA", (S, S), (0, 0, 0, 0)); o.paste(bgim, mask=mk)
    return o.resize((size, size), Image.LANCZOS)

def notif_preview(size):
    S = size * 8
    g = glyph_layers(S, NOTIF_SCALE * S / 24, (S/2, S/2), mono=True)
    bg = Image.new("RGBA", (S, S), (40, 40, 44, 255)); bg.alpha_composite(g)
    return bg.resize((size, size), Image.LANCZOS)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--svg", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "master.svg"))
    ap.add_argument("--iconset"); ap.add_argument("--previews"); ap.add_argument("--android")
    a = ap.parse_args()
    with open(a.svg, "w", encoding="utf-8") as f:
        f.write(master_svg())
    if a.iconset:
        os.makedirs(a.iconset, exist_ok=True)
        for base in (16, 32, 128, 256, 512):
            for sc in (1, 2):
                px = base * sc
                if px <= 64:
                    img = render_master(px)   # downsample from 4096 directly
                else:
                    img = render_master(1024)
                    if px != 1024:
                        img = img.resize((px, px), Image.LANCZOS)
                img.save(os.path.join(a.iconset, f"icon_{base}x{base}{'@2x' if sc == 2 else ''}.png"))
    if a.previews:
        os.makedirs(a.previews, exist_ok=True)
        for px in (1024, 128, 32, 16): render_master(px).save(f"{a.previews}/icon-{px}.png")
        # enlarged 16/32 views for inspection
        for px in (16, 32): render_master(px).resize((256, 256), Image.NEAREST).save(f"{a.previews}/icon-{px}-zoom.png")
        adaptive_preview(432, "circle").save(f"{a.previews}/icon-android-circle.png")
        adaptive_preview(432, "squircle").save(f"{a.previews}/icon-android-squircle.png")
        adaptive_preview(432, "circle", mono=True).save(f"{a.previews}/icon-android-mono.png")
        notif_preview(48).resize((288, 288), Image.NEAREST).save(f"{a.previews}/icon-android-notif.png")
    if a.android: write_android(a.android)

if __name__ == "__main__":
    main()
