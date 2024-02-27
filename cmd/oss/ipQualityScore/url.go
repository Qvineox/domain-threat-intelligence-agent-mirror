package ipQualityScore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func (s *ScannerImpl) scanURL(url string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/url/"+s.Config.APIKey+"/"+url, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")

	query := request.URL.Query()
	query.Add("strictness", "1") // TODO: remove constant query value

	response, err := s.Client.Do(request)
	if response.StatusCode == http.StatusOK {
		_, err = response.Body.Read(body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from IPQualityScore: %s", err.Error()))
		}
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from IPQualityScore: %s", e.Message))
		}

		return nil, errors.New(fmt.Sprintf("failed to query URL '%s' from IPQualityScore: %s", url, e.Message))
	}

	return body, nil
}
