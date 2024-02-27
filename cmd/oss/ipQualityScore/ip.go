package ipQualityScore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

func (s *ScannerImpl) scanIP(ip string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/ip/"+s.Config.APIKey+"/"+ip, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")

	query := request.URL.Query()

	// TODO: remove constant query values
	query.Add("strictness", "2")
	query.Add("transaction_strictness", "0")
	query.Add("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36")
	query.Add("user_language", "ru-RU")
	query.Add("mobile", strconv.FormatBool(false))
	query.Add("allow_public_access_points", strconv.FormatBool(true))
	query.Add("lighter_penalties", strconv.FormatBool(true))
	request.URL.RawQuery = query.Encode()

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

		return nil, errors.New(fmt.Sprintf("failed to query IP '%s' from IPQualityScore: %s", ip, e.Message))
	}

	return body, nil
}
