// see https://github.com/influxdata/influxdb/issues/5088

package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"log"
	"os"
	"math"

	"github.com/influxdata/kapacitor/udf"
	"github.com/influxdata/kapacitor/udf/agent"
)

// An Agent.Handler that computes a skewness of the data it receives.
type aHandler struct {
	field string
	as    string
	size  int
	state map[string]*aState

	agent *agent.Agent
}

// The state required to compute.
type aState struct {
	Size   int
	Window []float64
	Avg    float64
}

func Skewness(data []float64) float64 {

    /*

        Skewness is a measure of the asymmetry of the data around the sample mean.
        If skewness is negative, the data are spread out more to the left of the
        mean than to the right. If skewness is positive, the data are spread out
        more to the right.
        The skewness of the normal distribution is zero.

    */

    // shape of vector len of three, imagine that ;)
    if len(data) < 4 {
        return 0
    }

    // Get the mean
    var mean float64
    var count int
    for _, v := range data {
        count++
        mean += (v - mean) / float64(count)
    }
    // Get the variance
    var variance float64
    for _, v := range data {
        dif := v - mean
        sq := math.Pow(dif, 2)
        variance += sq
    }
    variance = math.Sqrt(variance / float64(count-1))

    // Get the skewness
    sum := 0.0
    for _, v := range data {
        delta := v - mean
        sum += delta * delta * delta
    }

    skewness := sum / float64(count) / (variance * variance * variance)

    return skewness

}

// Update  with the next data point.
func (a *aState) update(value float64) float64 {
	l := len(a.Window)
	if a.Size == l {
		a.Window = a.Window[1:]
	}
	a.Window = append(a.Window, value)
	return Skewness(a.Window)
}

func newMovingaHandler(a *agent.Agent) *aHandler {
	return &aHandler{
		state: make(map[string]*aState),
		as:    "skewness",
		agent: a,
	}
}

// Return the InfoResponse. Describing the properties of this UDF agent.
func (a *aHandler) Info() (*udf.InfoResponse, error) {
	info := &udf.InfoResponse{
		Wants:    udf.EdgeType_STREAM,
		Provides: udf.EdgeType_STREAM,
		Options: map[string]*udf.OptionInfo{
			"field": {ValueTypes: []udf.ValueType{udf.ValueType_STRING}},
			"size":  {ValueTypes: []udf.ValueType{udf.ValueType_INT}},
			"as":    {ValueTypes: []udf.ValueType{udf.ValueType_STRING}},
		},
	}
	return info, nil
}

// Initialze the handler based of the provided options.
func (a *aHandler) Init(r *udf.InitRequest) (*udf.InitResponse, error) {
	init := &udf.InitResponse{
		Success: true,
		Error:   "",
	}
	for _, opt := range r.Options {
		switch opt.Name {
		case "field":
			a.field = opt.Values[0].Value.(*udf.OptionValue_StringValue).StringValue
		case "size":
			a.size = int(opt.Values[0].Value.(*udf.OptionValue_IntValue).IntValue)
		case "as":
			a.as = opt.Values[0].Value.(*udf.OptionValue_StringValue).StringValue
		}
	}

	if a.field == "" {
		init.Success = false
		init.Error += " must supply field"
	}
	if a.size == 0 {
		init.Success = false
		init.Error += " must supply window size"
	}
	if a.as == "" {
		init.Success = false
		init.Error += " invalid as name provided"
	}

	return init, nil
}

// Create a snapshot of the running state of the process.
func (a *aHandler) Snaphost() (*udf.SnapshotResponse, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(a.state)

	return &udf.SnapshotResponse{
		Snapshot: buf.Bytes(),
	}, nil
}

// Restore a previous snapshot.
func (a *aHandler) Restore(req *udf.RestoreRequest) (*udf.RestoreResponse, error) {
	buf := bytes.NewReader(req.Snapshot)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&a.state)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return &udf.RestoreResponse{
		Success: err == nil,
		Error:   msg,
	}, nil
}

// This handler does not do batching
func (a *aHandler) BeginBatch(*udf.BeginBatch) error {
	return errors.New("batching not supported")
}

// Receive a point and compute the skewness & send a response
func (a *aHandler) Point(p *udf.Point) error {
	value := p.FieldsDouble[a.field]
	state := a.state[p.Group]
	if state == nil {
		state = &aState{Size: a.size}
		a.state[p.Group] = state
	}
	avg := state.update(value)
	log.Println("got : %v", avg)

	// Re-use the existing point so we keep the same tags etc.
	p.FieldsDouble = map[string]float64{a.as: avg}
	p.FieldsInt = nil
	p.FieldsString = nil
	// Send point.
	a.agent.Responses <- &udf.Response{
		Message: &udf.Response_Point{
			Point: p,
		},
	}
	return nil
}

// This handler does not do batching
func (a *aHandler) EndBatch(*udf.EndBatch) error {
	return errors.New("batching not supported")
}

// Stop the handler gracefully.
func (a *aHandler) Stop() {
	log.Println("Stopping agent")
	close(a.agent.Responses)
}

func main() {
	a := agent.New(os.Stdin, os.Stdout)
	h := newMovingaHandler(a)
	a.Handler = h

	log.Println("Starting agent")
	a.Start()
	err := a.Wait()
	if err != nil {
		log.Fatal(err)
	}
}
