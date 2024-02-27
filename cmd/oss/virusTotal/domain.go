package virusTotal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func (s *ScannerImpl) scanDomain(domain string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/domains/"+domain, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")
	request.Header.Add("x-apikey", s.Config.APIKey)

	response, err := s.Client.Do(request)
	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from VirusTotal: %s", err.Error()))
		}
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from VirusTotal: %s", err.Error()))
		}

		return nil, errors.New(fmt.Sprintf("failed to query DOMAIN '%s' from VirusTotal: %s", domain, e.Error.Message))
	}

	return body, nil
}
