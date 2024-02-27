package ipQualityScore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

func (s *ScannerImpl) scanEmail(email string) (body []byte, err error) {
	request, err := http.NewRequest("GET", s.Config.BaseURL+"/email/"+s.Config.APIKey+"/"+email, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("accept", "application/json")

	query := request.URL.Query()

	// TODO: remove constant query values
	query.Add("strictness", "2")
	query.Add("abuse_strictness", "0")
	query.Add("suggest_domain", strconv.FormatBool(true))

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

		return nil, errors.New(fmt.Sprintf("failed to query EMAIL '%s' from IPQualityScore: %s", email, e.Message))
	}

	return body, nil
}
