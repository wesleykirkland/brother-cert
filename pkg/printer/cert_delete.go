package printer

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const urlCertDelete = "/net/security/certificate/delete.html"

var errCertDeleteInvalidID = errors.New("printer: cant delete cert (invalid id)")

// deleteFormFields holds the dynamically discovered form field names for the delete page
type deleteFormFields struct {
	hiddenField1 string // first hidden field (e.g., B8ea or Bb0a)
	hiddenField2 string // second hidden field (e.g., B8fc or Bb1c)
}

// parseDeleteFormFields extracts the form field names from the delete page HTML
func parseDeleteFormFields(bodyBytes []byte) (*deleteFormFields, error) {
	fields := &deleteFormFields{}

	// Find hidden fields that are NOT CSRFToken, pageid, hidden_certificate_process_control, or hidden_certificate_idx
	// Pattern: <input type="hidden" id="Bb0a" name="Bb0a" value="" />
	hiddenRegex := regexp.MustCompile(`<input[^>]+type="hidden"[^>]+(?:id="([^"]+)"[^>]+name="([^"]+)"|name="([^"]+)"[^>]+id="([^"]+)")[^>]*value=""[^>]*>`)
	hiddenMatches := hiddenRegex.FindAllSubmatch(bodyBytes, -1)

	hiddenFields := []string{}
	for _, match := range hiddenMatches {
		var fieldName string
		if len(match[1]) > 0 {
			fieldName = string(match[1])
		} else if len(match[3]) > 0 {
			fieldName = string(match[3])
		}

		// Skip known fields
		if fieldName != "" && fieldName != "CSRFToken" && fieldName != "CSRFToken1" &&
			fieldName != "pageid" && fieldName != "hidden_certificate_process_control" &&
			fieldName != "hidden_certificate_idx" {
			hiddenFields = append(hiddenFields, fieldName)
		}
	}

	if len(hiddenFields) >= 2 {
		fields.hiddenField1 = hiddenFields[0]
		fields.hiddenField2 = hiddenFields[1]
	}

	return fields, nil
}

// DeleteCert deletes the certificate with the specified ID from the
// printer
func (p *printer) DeleteCert(id string) error {
	// verify ID actually exists and isn't 0 ('Preset') which isn't valid
	if len(id) <= 0 || id == "0" {
		return errCertDeleteInvalidID
	}

	existingIDs, err := p.getCertIDs()
	if err != nil {
		return err
	}

	validID := false
	for _, existingID := range existingIDs {
		if existingID == id {
			validID = true
			break
		}
	}
	if !validID {
		return errCertDeleteInvalidID
	}

	// first get the delete page to get CSRFToken
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = urlCertDelete

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	// req query
	query := req.URL.Query()
	query.Set("idx", id)
	req.URL.RawQuery = query.Encode()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("printer: get of delete page failed (status code %d)", resp.StatusCode)
	}

	// find CSRFToken
	csrfToken, err := parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return err
	}

	// parse form field names from the delete page HTML
	formFields, err := parseDeleteFormFields(bodyBytes)
	if err != nil {
		return err
	}

	// first delete form
	// form values
	data := url.Values{}
	data.Set("pageid", "383")
	data.Set("CSRFToken", csrfToken)
	// use dynamically discovered hidden field names
	if formFields.hiddenField1 != "" {
		data.Set(formFields.hiddenField1, "")
	}
	if formFields.hiddenField2 != "" {
		data.Set(formFields.hiddenField2, "")
	}
	data.Set("hidden_certificate_process_control", "1")
	data.Set("hidden_certificate_idx", id)

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = urlCertDelete

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("printer: get failed (status code %d)", resp.StatusCode)
	}

	// find CSRFToken
	csrfToken, err = parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return err
	}

	// parse form field names from the confirmation page HTML
	confirmFormFields, err := parseDeleteFormFields(bodyBytes)
	if err != nil {
		return err
	}

	// second delete (confirmation) form
	// form values
	data = url.Values{}
	data.Set("pageid", "383")
	data.Set("CSRFToken", csrfToken)
	// use dynamically discovered hidden field names from confirmation page
	if confirmFormFields.hiddenField1 != "" {
		data.Set(confirmFormFields.hiddenField1, "")
	}
	if confirmFormFields.hiddenField2 != "" {
		data.Set(confirmFormFields.hiddenField2, "")
	}
	data.Set("hidden_certificate_process_control", "2")
	data.Set("hidden_certificate_idx", id)

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = urlCertDelete

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read and discard entire body
	_, _ = io.Copy(io.Discard, resp.Body)

	// normally the webUI would show a waiting screen for ~7 seconds. insert
	// a delay here to account for any processing the device might do
	// before next steps
	time.Sleep(10 * time.Second)

	// check id list and ensure its gone
	existingIDs, err = p.getCertIDs()
	if err != nil {
		return err
	}

	idFound := false
	for _, existingID := range existingIDs {
		if existingID == id {
			idFound = true
			break
		}
	}
	if idFound {
		return errors.New("printer: failed to delete cert (still exists)")
	}

	return nil
}
