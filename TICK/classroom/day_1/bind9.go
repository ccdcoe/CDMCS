package bind9

import (
  "fmt"
  "net/http"
  "encoding/xml"
  "os"
  "strconv"
  "strings"
  "github.com/influxdata/telegraf"
  "github.com/influxdata/telegraf/plugins/inputs"
)

type Bind9 struct {
  Host string `toml:"host"`
  Port int `toml:"port"`
}
func (s *Bind9) Description() string {
  return "a bind9 plugin"
}
func (s *Bind9) SampleConfig() string {
  return `
  # bind9 stats channel
  host = "127.0.0.1"
  # bind9 stats port
  port = 8080
`
}

type Root struct {
  IscVersion string `xml:"version,attr"`
  BootTime string `xml:"server>boot-time"`
  ServerStats []Counters `xml:"server>counters"`
  Views []View `xml:"views>view"`
}
type Counters struct {
  Key string `xml:"type,attr"`
  Stats []Stat `xml:"counter"`
}
type View struct {
  Key string `xml:"name,attr"`
  ViewStats []Counters `xml:"counters"`
}
type Stat struct {
  Key string `xml:"name,attr"`
  Value int `xml:",chardata"`
}

func (s *Bind9) Gather(acc telegraf.Accumulator) error {
  c := "http://" + s.Host + ":" + strconv.Itoa(s.Port)
  response, err := http.Get(c)
  if err != nil {
    fmt.Printf("%s", err)
    os.Exit(1)
  } else {
    defer response.Body.Close()
    if err != nil {
      fmt.Printf("%s", err)
      os.Exit(1)
    }
    var query Root
    xml.NewDecoder(response.Body).Decode(&query)

    fields := make(map[string]interface{})
    tags := make(map[string]string)

    for _, counter := range query.ServerStats {
      //fmt.Printf("\t%s\n", counter.Key)
      for _, stat := range counter.Stats {
        //v := strconv.Itoa(stat.Value)
        //fmt.Printf("\t\t%s:%s\n", stat.Key, v)
        fields[stat.Key] = stat.Value
      }
      s := []string{"bind9", counter.Key};
      acc.AddFields(strings.Join(s, "_"), fields, tags);
      for k := range fields { delete(fields, k) }
    }
    for _, view := range query.Views {
      //fmt.Printf("\t%s\n", view.Key)
      tags["view"] = view.Key
      for _, stat := range view.ViewStats {
        //tags["type"] = stat.Key
        for _, counter := range stat.Stats {
          //v := strconv.Itoa(counter.Value)
          //fmt.Printf("\t\t%s:%s\n", counter.Key, v)
          fields[counter.Key] = counter.Value
        }
        s := []string{"bind9", stat.Key};
        acc.AddFields(strings.Join(s, "_"), fields, tags);
        for k := range fields { delete(fields, k) }
      }
    }
  }
  return nil
}

func init() {
  inputs.Add("bind9", func() telegraf.Input {
    return &Bind9{}
  })
}
