// Go-runtime spawn case: 4 goroutines spawn a child through the Go
// runtime's raw clone+execve path while the main goroutine parks.
// Built by tests/suite.sh when a Go toolchain is available.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := exec.Command("./testcases", "sleeper", "MARKERGO")
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				fmt.Println("run err:", err)
			}
		}()
	}
	wg.Wait()
	select {} // stay alive so observers can look
}
