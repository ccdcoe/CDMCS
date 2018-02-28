package main

import (
	"archive/zip"
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"strings"
)

// Reservoir implements simple reservoir filter
type Reservoir struct {
	k        int
	total    uint64
	switches uint64
	sample   []interface{}
}

// InitReservoir instantiates new Reservoir struct
func InitReservoir(k int) (r *Reservoir, err error) {
	r = &Reservoir{
		k:        k,
		total:    0,
		switches: 0,
		sample:   make([]interface{}, k),
	}
	return r, nil
}

// Add new item to reservoir
func (r *Reservoir) Add(item interface{}) *Reservoir {
	r.total++
	if len(r.sample) < r.k {
		r.sample = append(r.sample, item)
	} else {
		if rand.Float64() < (float64(r.k) / float64(r.total)) {
			r.sample[rand.Intn(r.k)] = item
			r.switches++
		}
	}
	return r
}

// GetSample is a helper to return size of sampled data
func (r *Reservoir) GetSample() []interface{} {
	return r.sample
}

// total no items seen
func (r *Reservoir) GetTotal() uint64 {
	return r.total
}

// GetSwitches is a helper to return number of items seen
func (r *Reservoir) GetSwitches() uint64 {
	return r.switches
}

func main() {
	r, err := zip.OpenReader("/home/markus/data/SDM/logs/log20170630.zip")
	if err != nil {
		log.Fatal(err)
	}

	k := 5000
	reservoir, err := InitReservoir(k)

	defer r.Close()
	for _, f := range r.File {
		if f.Name != "README.txt" {
			rc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer rc.Close()
			byline := bufio.NewScanner(rc)
			var data []string
			lines := 0
			for byline.Scan() {
				lines++
				data = strings.Split(byline.Text(), ",")
				ipv4 := data[0]
				reservoir.Add(ipv4)
			}
		}
	}

	//sample := reservoir.GetSample()
	fmt.Println("no switched items:", reservoir.GetSwitches())
	fmt.Println("total items seen:", reservoir.GetTotal())
}
