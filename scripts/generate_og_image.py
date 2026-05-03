#!/usr/bin/env python3
"""Generate the og-image.png link-preview card for kite-mcp-server.

Output: 1200x630 PNG with the README hero value-prop (~70 words),
three CTA labels, and the install command. Text-only — no logo,
no chart, no theme. Render-on-build approach: re-run this script
whenever the value-prop changes.

Usage:
    python scripts/generate_og_image.py

Writes: kc/templates/static/og-image.png
"""
from PIL import Image, ImageDraw, ImageFont
import os
import sys

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "kc",
    "templates",
    "static",
    "og-image.png",
)

WIDTH = 1200
HEIGHT = 630

# Theme — match the dark landing page aesthetic
BG_COLOR = (12, 14, 18)       # near-black, slight blue tint
ACCENT = (97, 218, 251)       # cyan accent for headers
TEXT_PRIMARY = (235, 240, 250)
TEXT_SECONDARY = (170, 180, 195)
BORDER = (50, 60, 75)


def find_font(candidates, size):
    """Return the first font in `candidates` that PIL can load, fallback default."""
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except (IOError, OSError):
            continue
    return ImageFont.load_default()


def main():
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Subtle border around the canvas
    draw.rectangle([(20, 20), (WIDTH - 20, HEIGHT - 20)], outline=BORDER, width=2)

    # Resolve fonts. Try Inter, Segoe UI (Windows), then DejaVu (Linux).
    font_candidates_bold = [
        r"C:\Windows\Fonts\segoeuib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/SFCompactDisplay-Bold.otf",
    ]
    font_candidates_regular = [
        r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/SFCompactDisplay-Regular.otf",
    ]
    font_candidates_mono = [
        r"C:\Windows\Fonts\consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/SFMono-Regular.otf",
    ]

    title_font = find_font(font_candidates_bold, 56)
    sub_font = find_font(font_candidates_regular, 30)
    body_font = find_font(font_candidates_regular, 28)
    cta_font = find_font(font_candidates_bold, 24)
    code_font = find_font(font_candidates_mono, 22)
    footer_font = find_font(font_candidates_regular, 22)

    # Top: brand
    draw.text((60, 60), "Kite MCP Server", font=title_font, fill=TEXT_PRIMARY)
    draw.text(
        (60, 130),
        "Open-source Zerodha Kite copilot for Claude / ChatGPT",
        font=sub_font,
        fill=ACCENT,
    )

    # Body: value-prop, ~3 lines
    body_lines = [
        "117 tools. Order placement, paper trading, options Greeks,",
        "backtesting, Telegram alerts, 9 pre-trade safety checks.",
        "Per-user OAuth. AES-256-GCM at rest. MIT licensed.",
    ]
    y = 210
    for line in body_lines:
        draw.text((60, y), line, font=body_font, fill=TEXT_PRIMARY)
        y += 42

    # CTAs strip
    cta_y = 380
    cta_x = 60
    cta_items = [
        ("Hosted demo", ACCENT),
        ("  ·  ", TEXT_SECONDARY),
        ("Self-host", ACCENT),
        ("  ·  ", TEXT_SECONDARY),
        ("Compare vs official", ACCENT),
    ]
    for text, color in cta_items:
        draw.text((cta_x, cta_y), text, font=cta_font, fill=color)
        bbox = draw.textbbox((cta_x, cta_y), text, font=cta_font)
        cta_x = bbox[2]

    # Install command in a code-block style
    code_y = 450
    code_box_x0 = 60
    code_box_y0 = code_y - 12
    code_box_x1 = WIDTH - 60
    code_box_y1 = code_y + 50
    draw.rectangle(
        [(code_box_x0, code_box_y0), (code_box_x1, code_box_y1)],
        fill=(20, 24, 30),
        outline=BORDER,
        width=1,
    )
    install_cmd = "claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp"
    draw.text((75, code_y), install_cmd, font=code_font, fill=TEXT_PRIMARY)

    # Footer
    draw.text(
        (60, HEIGHT - 80),
        "github.com/Sundeepg98/kite-mcp-server",
        font=footer_font,
        fill=TEXT_SECONDARY,
    )
    draw.text(
        (WIDTH - 350, HEIGHT - 80),
        "16,209 tests · MIT · Go 1.25",
        font=footer_font,
        fill=TEXT_SECONDARY,
    )

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    img.save(OUTPUT_PATH, format="PNG", optimize=True)
    print(f"Wrote {OUTPUT_PATH} ({os.path.getsize(OUTPUT_PATH)} bytes)")


if __name__ == "__main__":
    main()
