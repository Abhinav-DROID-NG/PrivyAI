package benchmarks

import (
	"strconv"
	"strings"
	"testing"

	privyai "github.com/Abhinav-DROID-NG/PrivyAI"
)

func BenchmarkEngine(b *testing.B) {
	engine, err := privyai.New(privyai.DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range []int{100, 10_000, 1_000_000} {
		input := strings.Repeat("clean text ", size/11+1)[:size]
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := engine.Process(input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
