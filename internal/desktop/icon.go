package desktop

import (
	"image"
	"image/color"
	"math"
)

// Icon draws the app's mark at any size: the panel's favicon (a blue
// rounded square with the chain of three servers) and, for the tray, a
// status dot in the corner.

var statusColors = map[string]color.NRGBA{
	"ok":   {0x52, 0xc4, 0x1a, 0xff},
	"bad":  {0xff, 0x4d, 0x4f, 0xff},
	"wait": {0xfa, 0xad, 0x14, 0xff},
	"off":  {0x8c, 0x8c, 0x8c, 0xff},
}

// Icon draws the mark; status (ok, bad, wait, off or "") adds the tray dot.
func Icon(size int, status string) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	dot, hasDot := statusColors[status]
	const ss = 4 // supersampling per axis
	k := 32 / float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					// sample point in the 32×32 design space
					x := (float64(px) + (float64(sx)+0.5)/ss) * k
					y := (float64(py) + (float64(sy)+0.5)/ss) * k
					c := shade(x, y, hasDot, dot)
					r += float64(c.R) * float64(c.A)
					g += float64(c.G) * float64(c.A)
					b += float64(c.B) * float64(c.A)
					a += float64(c.A)
				}
			}
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a / (ss * ss))})
			}
		}
	}
	return img
}

// shade is the colour at a point of the design.
func shade(x, y float64, hasDot bool, dot color.NRGBA) color.NRGBA {
	white := color.NRGBA{0xff, 0xff, 0xff, 0xff}
	if hasDot {
		// the status dot with a white ring, bottom right
		d := math.Hypot(x-25, y-25)
		if d <= 6 {
			return dot
		}
		if d <= 7.6 {
			return white
		}
	}
	if !inRoundRect(x, y, 0, 0, 32, 32, 7) {
		return color.NRGBA{}
	}
	blue := color.NRGBA{0x16, 0x77, 0xff, 0xff}
	for _, c := range [][2]float64{{8, 16}, {16, 9}, {24, 16}} {
		if math.Hypot(x-c[0], y-c[1]) <= 3.2 {
			return white
		}
	}
	if segDist(x, y, 8, 16, 16, 9) <= 1 || segDist(x, y, 16, 9, 24, 16) <= 1 {
		return white
	}
	if math.Hypot(x-16, y-23) <= 3.2 {
		return color.NRGBA{0xa2, 0xc9, 0xff, 0xff} // white at 60% over the blue
	}
	return blue
}

func inRoundRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || y < y0 || x > x1 || y > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return math.Hypot(x-cx, y-cy) <= r
}

func segDist(x, y, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((x-ax)*dx + (y-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(x-(ax+t*dx), y-(ay+t*dy))
}
