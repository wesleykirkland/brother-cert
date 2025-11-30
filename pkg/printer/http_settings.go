package printer

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const urlHttpCertServerSettings = "net/net/certificate/http.html"

var (
	errCurrentCertIdNotFound = errors.New("printer: get: failed to find current cert id")
)

// httpSettingsFormFields holds the dynamically discovered form field names for the HTTP settings page
type httpSettingsFormFields struct {
	certSelectField string // certificate select dropdown (e.g., B903 or Bb23)
	httpsWebField   string // HTTPS checkbox for WebUI (e.g., B86c or Ba8c)
	httpsIppField   string // HTTPS checkbox for IPP (e.g., B87e or Ba9e)
}

// parseHttpSettingsFormFields extracts the form field names from the HTTP settings page HTML
func parseHttpSettingsFormFields(bodyBytes []byte) (*httpSettingsFormFields, error) {
	fields := &httpSettingsFormFields{}

	// Find the select element for certificate selection
	// Pattern: <select id="Bb23" name="Bb23" ...>
	selectRegex := regexp.MustCompile(`<select[^>]+(?:id="([^"]+)"[^>]+name="([^"]+)"|name="([^"]+)"[^>]+id="([^"]+)")[^>]*>`)
	selectMatch := selectRegex.FindSubmatch(bodyBytes)
	if len(selectMatch) >= 2 {
		if len(selectMatch[1]) > 0 {
			fields.certSelectField = string(selectMatch[1])
		} else if len(selectMatch[3]) > 0 {
			fields.certSelectField = string(selectMatch[3])
		}
	}

	// Find HTTPS checkboxes - look for checkboxes with HTTPS in surrounding context
	// The WebUI HTTPS checkbox typically has id like "Ba8c" and is near "HTTPS(Port 443)" text
	// Pattern: <input type="checkbox" id="Ba8c" name="Ba8c" value="1" checked="checked" />HTTPS
	httpsCheckboxRegex := regexp.MustCompile(`<input[^>]+type="checkbox"[^>]+(?:id="([^"]+)"[^>]+name="([^"]+)"|name="([^"]+)"[^>]+id="([^"]+)")[^>]+value="1"[^>]*>[^<]*HTTPS`)
	httpsMatches := httpsCheckboxRegex.FindAllSubmatch(bodyBytes, -1)

	for i, match := range httpsMatches {
		var fieldName string
		if len(match[1]) > 0 {
			fieldName = string(match[1])
		} else if len(match[3]) > 0 {
			fieldName = string(match[3])
		}

		if fieldName != "" {
			if i == 0 {
				fields.httpsWebField = fieldName
			} else if i == 1 {
				fields.httpsIppField = fieldName
			}
		}
	}

	// Validate we found required fields
	if fields.certSelectField == "" {
		return nil, errors.New("printer: http settings: failed to find certificate select field name")
	}

	return fields, nil
}

// getHttpSettings fetches the HTTP Server Settings page
func (p *printer) getHttpSettings() ([]byte, error) {
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return nil, err
	}
	u.Path = urlHttpCertServerSettings

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("printer: get of http settings page failed (status code %d)", resp.StatusCode)
	}

	return bodyBytes, nil
}

// SetActiveCert sets the printers active certificate the specified ID and
// then restarts the printer (to make the new cert active)
// Note: This function even works of the `id` is not in the dropdown box of the printer's
// cert picker (which happens when the cert does not have a Common Name)
func (p *printer) SetActiveCert(id string) error {
	// GET http settings
	bodyBytes, err := p.getHttpSettings()
	if err != nil {
		return err
	}

	// find CSRFToken
	csrfToken, err := parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return err
	}

	// parse form field names from the HTTP settings page HTML
	formFields, err := parseHttpSettingsFormFields(bodyBytes)
	if err != nil {
		return err
	}

	// submit initial form to change the cert
	data := url.Values{}
	data.Set("pageid", "326")
	data.Set("CSRFToken", csrfToken)
	// use dynamically discovered certificate select field name
	data.Set(formFields.certSelectField, id)
	// Enable HTTPS for WebUI and IPP using dynamically discovered field names
	if formFields.httpsWebField != "" {
		data.Set(formFields.httpsWebField, "1")
	}
	if formFields.httpsIppField != "" {
		data.Set(formFields.httpsIppField, "1")
	}
	// there are some other values here but don't set them (which should
	// leave them as-is in most cases)

	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = urlHttpCertServerSettings

	// make and do request
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
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
		return errors.New("printer: failed to post set active cert form")
	}

	// find next CSRFToken
	csrfToken, err = parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return err
	}

	// submit confirmation (& reboot now)
	data = url.Values{}
	data.Set("pageid", "326")
	data.Set("CSRFToken", csrfToken)
	// 4 == do NOT activate other secure protos
	// 5 == DO activate other secure protos
	data.Set("http_page_mode", "5")

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = urlHttpCertServerSettings

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
	_, _ = io.Copy(io.Discard, resp.Body)

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return errors.New("printer: failed to post set active cert form")
	}

	return nil
}
