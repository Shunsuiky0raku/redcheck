package ui

import (
	"fmt"
	"time"
)

func Spinner(stop <-chan bool) {
	frames := []rune{'|', '/', '-', '\\'}
	i := 0
	for {
		select {
		case <-stop:
			fmt.Print("\r") // clear line
			return
		default:
			fmt.Printf("\rScanning... %c", frames[i%len(frames)])
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}
}
