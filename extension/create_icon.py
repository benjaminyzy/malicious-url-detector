import os
from PIL import Image, ImageDraw

SIZE = 128
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Shield polygon points (normalised to 128x128)
shield = [
    (64, 8),    # top center
    (112, 28),  # top right
    (112, 68),  # right shoulder
    (64, 120),  # bottom tip
    (16, 68),   # left shoulder
    (16, 28),   # top left
]

# Fill and outline
draw.polygon(shield, fill=(34, 197, 94, 255))       # green fill
draw.polygon(shield, outline=(21, 128, 61, 255))     # darker green border, 1px

# White checkmark  ✓  inside the shield
check = [
    (40, 64),
    (56, 82),
    (88, 46),
    (93, 52),
    (56, 92),
    (35, 70),
]
draw.polygon(check, fill=(255, 255, 255, 230))

out_dir = os.path.join(os.path.dirname(__file__), "icons")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "shield.png")
img.save(out_path)
print(f"Saved {out_path}")
