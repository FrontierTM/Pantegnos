package utils

import (
	"fmt"
	"strings"

	"github.com/mazznoer/colorgrad"
)

func ColorizeGradientText(text string, grad colorgrad.Gradient) string {
	var colorized strings.Builder
	text = strings.Replace(text, "\r\n", "\n", -1)

	if strings.Contains(text, "\n") {
		for _, line := range strings.Split(text, "\n") {
			coloredLine := ColorizeGradientText(line, grad)
			colorized.WriteString(coloredLine + "\r\n")
		}
		return strings.TrimSuffix(colorized.String(), "\r\n")
	}

	runes := []rune(text)
	length := len(runes)
	for i := 0; i < length; i++ {
		color := grad.At(float64(i) / float64(length-1))
		red, green, blue, _ := color.RGBA255()
		colorized.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm%c\x1b[0m", red, green, blue, runes[i]))
	}
	return colorized.String()
}
