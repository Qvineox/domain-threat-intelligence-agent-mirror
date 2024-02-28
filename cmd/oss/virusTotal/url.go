package virusTotal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func (s *ScannerImpl) scanURL(url_ string) (body []byte, err error) {
	url_ = url.PathEscape(url_)

	request, err := http.NewRequest("GET", s.Config.BaseURL+"/urls/"+url_, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")
	request.Header.Add("x-apikey", s.Config.APIKey)

	response, err := s.Client.Do(request)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to connect to VirusTotal: %s", err.Error()))
	}

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

		return nil, errors.New(fmt.Sprintf("failed to query URL '%s' from VirusTotal: %s", url_, e.Error.Message))
	}

	return body, nil
}
