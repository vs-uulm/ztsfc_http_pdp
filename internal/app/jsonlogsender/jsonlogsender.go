package jsonlogsender

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

type JSONLogSender struct {
	HookURL string
	client  *http.Client
}

type LogToSend struct {
	TimeStamp   int64
	Job         string
	ThreatLevel int
	User        string
	Uts         string
	Device      string
	Dts         string
	Tts         string
	Resource    string
	Action      string
	Decision    string
	Reason      string
	Sfc         string
}

func New(url string) (*JSONLogSender, error) {
	if url == "" {
		return nil, fmt.Errorf("jsonlogsender: New(): unable to create a new log sender: empty URL")
	}

	return &JSONLogSender{
		HookURL: url,
		client:  &http.Client{},
	}, nil
}

func (ls *JSONLogSender) Send(job, threatLevel, user, uts, device, dts, tts, resource, action, decision, reason string, sfc string) error {
	s := fmt.Sprintf(`{"streams": [
		{"stream":
			{"job": "%s",
			 "tl": "%s",
			 "uts": "%s",
			 "device": "%s",
			 "dts": "%s",
			 "tts": "%s",
			 "resource": "%s",
			 "action": "%s", 
			 "decision": "%s",
			 "reason": "%s",
			 "sfc": "%s"},
		 "values":
		 	[[ "%d", {"user": "%s", "mes":"messageABC"} ]]}
	]}`, job, threatLevel, uts, device, dts, tts, resource, action, decision, reason, sfc, time.Now().UnixNano(), user)

	fmt.Printf("JSON log to be sent: %s\n", s)

	req, err := http.NewRequest("POST", ls.HookURL, bytes.NewBuffer([]byte(s)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := ls.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
