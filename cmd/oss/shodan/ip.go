package shodan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func (s *ScannerImpl) scanIP(ip string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/host/"+ip, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")

	query := request.URL.Query()
	query.Add("key", s.Config.APIKey)

	request.URL.RawQuery = query.Encode()

	response, err := s.Client.Do(request)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to connect to Shodan: %s", err.Error()))
	}

	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from Shodan: %s", err.Error()))
		}
	} else if response.StatusCode == http.StatusUnauthorized {
		return nil, errors.New(fmt.Sprintf("failed to query IP '%s' from Shodan: %s", ip, "http status 401 (unauthorized)"))
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from Shodan: %s", err.Error()))
		}

		return nil, errors.New(fmt.Sprintf("failed to query IP '%s' from Shodan: %s", ip, e.Error))
	}

	return body, nil
}
