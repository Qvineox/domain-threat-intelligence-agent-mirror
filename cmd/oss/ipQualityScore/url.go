package ipQualityScore

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

	request, err := http.NewRequest("GET", s.Config.BaseURL+"/url/"+s.Config.APIKey+"/"+url_, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")

	query := request.URL.Query()
	query.Add("strictness", "1") // TODO: remove constant query value

	response, err := s.Client.Do(request)
	if response.StatusCode == http.StatusOK {
		body, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to read message from IPQualityScore: %s", err.Error()))
		}
	} else if response.StatusCode == http.StatusUnauthorized {
		return nil, errors.New(fmt.Sprintf("failed to query URL '%s' from IPQualityScore: %s", url_, "http status 401 (unauthorized)"))
	} else {
		var e apiError

		err = json.NewDecoder(response.Body).Decode(&e)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to decode error message from IPQualityScore: %s", err.Error()))
		}

		return nil, errors.New(fmt.Sprintf("failed to query URL '%s' from IPQualityScore: %s", url_, e.Message))
	}

	return body, nil
}
