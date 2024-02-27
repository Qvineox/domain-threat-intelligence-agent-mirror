package virusTotal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (s *ScannerImpl) scanIP(ip string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/ip_addresses/"+ip, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")
	request.Header.Add("x-apikey", s.Config.APIKey)

	response, err := s.Client.Do(request)
	if response.StatusCode == http.StatusOK {
		_, err = response.Body.Read(body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from VirusTotal: %s", err.Error()))
		}
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from VirusTotal: %s", e.Error.Message))
		}

		return nil, errors.New(fmt.Sprintf("failed to query IP '%s' from VirusTotal: %s", ip, e.Error.Message))
	}

	return body, nil
}
