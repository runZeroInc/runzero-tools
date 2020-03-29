package rnd

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// CounterPredictor tries to predict the next sequence based on a detected cyclical pattern
type CounterPredictor struct {
	MinRep     int
	MinLen     int
	cycle      []uint64
	samples    []uint64
	history    []uint64
	cycleIndex int
	lastSample uint64
	m          sync.Mutex
}

// SubmitSample is used to train the predictor
func (c *CounterPredictor) SubmitSample(v uint64) bool {
	c.m.Lock()
	defer c.m.Unlock()

	if c.lastSample == 0 {
		c.lastSample = v
		return false
	}

	c.samples = append(c.samples, v-c.lastSample)
	c.history = append(c.history, v)
	c.lastSample = v
	return c.predictCycle()
}

// Ready indicates if the predictor has calculted the cycle
func (c *CounterPredictor) Ready() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return len(c.cycle) > 0
}

// GetCycle returns the predicted cycle
func (c *CounterPredictor) GetCycle() []uint64 {
	c.m.Lock()
	defer c.m.Unlock()
	if len(c.cycle) == 0 {
		return []uint64{}
	}
	res := make([]uint64, len(c.cycle))
	copy(res, c.cycle)
	return res
}

// GetSampleCount returns the number of samples stored
func (c *CounterPredictor) GetSampleCount() int {
	c.m.Lock()
	defer c.m.Unlock()
	return len(c.samples)
}

func (c *CounterPredictor) predictCycle() bool {
	if len(c.samples) < (c.MinRep * c.MinLen) {
		return false
	}

	endSearch := len(c.samples) - ((c.MinRep - 1) * c.MinLen)
	// log.Printf("samples: %d (rep:%d, len:%d) end:%d", len(c.samples), c.MinRep, c.MinLen, endSearch)

	allSamples := U64SliceToSeq(c.samples[:])

	for i := 0; i < endSearch; i++ {
		for x := c.MinLen; x <= (c.MinLen * 10); x++ {

			canLen := i + x
			if canLen >= len(c.samples) {
				break
			}

			can := c.samples[i:canLen]

			canStr := U64SliceToSeq(can)

			canTest := ""
			for y := 0; y <= c.MinRep; y++ {
				canTest = canTest + "-" + canStr
			}

			// log.Printf("[%d/%d/%d] can: %v", i, x, canLen, canStr)
			if strings.Contains(allSamples, canTest) {
				c.cycle = can
				c.calculateCycleIndex()
				return true
			}
		}
	}

	return false
}

// Check submits a new value and returns the list of missing sequences if any
func (c *CounterPredictor) Check(v uint64) ([]uint64, error) {
	c.m.Lock()
	defer c.m.Unlock()

	foundSessions := []uint64{}

	if len(c.cycle) == 0 {
		return foundSessions, nil
	}

	last := c.history[len(c.history)-1]
	pred := last + c.cycle[c.cycleIndex]

	for pred != v {

		foundSessions = append(foundSessions, pred)

		// The predictor lost sync, better to recalibrate than try to fix it
		if len(foundSessions) > 100 {
			return []uint64{}, fmt.Errorf("predictor lost sync")
		}

		c.cycleIndex = (c.cycleIndex + 1) % len(c.cycle)

		c.history = append(c.history, pred)
		if len(c.history) > 512 {
			c.history = c.history[len(c.history)-512:]
		}

		last = c.history[len(c.history)-1]
		pred = last + c.cycle[c.cycleIndex]
	}

	// Update cycle index
	c.cycleIndex = (c.cycleIndex + 1) % len(c.cycle)

	// Determine the expected value based on the cycle

	// Update the history
	c.history = append(c.history, v)
	if len(c.history) > 512 {
		c.history = c.history[len(c.history)-512:]
	}

	return foundSessions, nil
}

// Previous rolls back to the prior session ID using the predicted counter
func (c *CounterPredictor) Previous(v uint64) (uint64, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if len(c.cycle) == 0 {
		return 0, fmt.Errorf("no cycle")
	}

	// Update cycle index
	c.cycleIndex = c.cycleIndex - 1

	if c.cycleIndex < 0 {
		c.cycleIndex = len(c.cycle) - 1
	}

	// Calculate the previous sequence
	prev := v - c.cycle[c.cycleIndex]

	return prev, nil
}

func (c *CounterPredictor) calculateCycleIndex() {
	hs := U64SliceToSeq(c.samples)
	cs := U64SliceToSeq(c.cycle)
	oc := strings.LastIndex(hs, cs)
	if oc == -1 {
		log.Printf("failed to calculate cycle index: %s in %s", cs, hs)
		return
	}

	cycleStart := hs[oc:]
	// log.Printf("cycle start: %s (%d)", cycleStart, oc)

	bits := strings.Split(cycleStart, "-")
	c.cycleIndex = len(bits) % len(c.cycle)
	// log.Printf("cycleIndex: %d (%x)", c.cycleIndex, c.cycle[c.cycleIndex])
}

// NewCounterPredictor returns a new instance of the predictor
func NewCounterPredictor(rep int, len int) *CounterPredictor {
	return &CounterPredictor{MinRep: rep, MinLen: len}
}
