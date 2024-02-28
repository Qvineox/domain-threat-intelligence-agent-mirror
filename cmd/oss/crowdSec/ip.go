package crowdSec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func (s *ScannerImpl) scanIP(ip string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/smoke/"+ip, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")
	request.Header.Add("x-api-key", s.Config.APIKey)

	response, err := s.Client.Do(request)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to connect to CrowdSec: %s", err.Error()))
	}

	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from CrowdSec: %s", err.Error()))
		}
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from CrowdSec: %s", err.Error()))
		}

		return nil, errors.New(fmt.Sprintf("failed to query IP '%s' from CrowdSec: %s", ip, e.Message))
	}

	return body, nil
}
