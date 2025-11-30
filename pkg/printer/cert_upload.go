package printer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const urlCertImport = "/net/security/certificate/import.html"

// importFormFields holds the dynamically discovered form field names for the import page
type importFormFields struct {
	hiddenField1  string // first hidden field (e.g., B8ea or Bb0a)
	hiddenField2  string // second hidden field (e.g., B8f8 or Bb18)
	fileField     string // file input field (e.g., B820 or Ba40)
	passwordField string // password field (e.g., B821 or Ba41)
}

// parseImportFormFields extracts the form field names from the import page HTML
func parseImportFormFields(bodyBytes []byte) (*importFormFields, error) {
	fields := &importFormFields{}

	// Find hidden fields that are NOT CSRFToken, pageid, or hidden_certificate_process_control
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
			fieldName != "hidden_cert_import_password" {
			hiddenFields = append(hiddenFields, fieldName)
		}
	}

	if len(hiddenFields) >= 2 {
		fields.hiddenField1 = hiddenFields[0]
		fields.hiddenField2 = hiddenFields[1]
	}

	// Find file input field
	// Pattern: <input type="file" ... id="Ba40" name="Ba40" ... />
	fileRegex := regexp.MustCompile(`<input[^>]+type="file"[^>]+(?:id="([^"]+)"|name="([^"]+)")[^>]*>`)
	fileMatch := fileRegex.FindSubmatch(bodyBytes)
	if len(fileMatch) >= 2 {
		if len(fileMatch[1]) > 0 {
			fields.fileField = string(fileMatch[1])
		} else if len(fileMatch[2]) > 0 {
			fields.fileField = string(fileMatch[2])
		}
	}

	// Find password input field
	// Pattern: <input type="password" ... id="Ba41" name="Ba41" ... />
	passwordRegex := regexp.MustCompile(`<input[^>]+type="password"[^>]+(?:id="([^"]+)"|name="([^"]+)")[^>]*>`)
	passwordMatch := passwordRegex.FindSubmatch(bodyBytes)
	if len(passwordMatch) >= 2 {
		if len(passwordMatch[1]) > 0 {
			fields.passwordField = string(passwordMatch[1])
		} else if len(passwordMatch[2]) > 0 {
			fields.passwordField = string(passwordMatch[2])
		}
	}

	// Validate we found required fields
	if fields.fileField == "" {
		return nil, errors.New("printer: upload: failed to find file input field name")
	}
	if fields.passwordField == "" {
		return nil, errors.New("printer: upload: failed to find password input field name")
	}

	return fields, nil
}

// UploadNewCert converts the specified pem files into p12 format and installs them
// on the printer. It returns the id value of the newly installed cert.
func (p *printer) UploadNewCert(keyPem, certPem []byte) (string, error) {
	// make p12 from key and cert pem
	p12, err := makeModernPfx(keyPem, certPem, "")
	if err != nil {
		return "", fmt.Errorf("printer: failed to make p12 file (%w)", err)
	}

	// GET current cert IDs
	origCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}

	// GET import page to obtain CSRFToken
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: get of certificate import page failed (status code %d)", resp.StatusCode)
	}

	// find CSRFToken
	csrfToken, err := parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return "", err
	}

	// parse form field names from the import page HTML
	formFields, err := parseImportFormFields(bodyBytes)
	if err != nil {
		return "", err
	}

	// make writer for multipart/form-data submission
	var formDataBuffer bytes.Buffer
	formWriter := multipart.NewWriter(&formDataBuffer)

	// make form fields
	err = formWriter.WriteField("pageid", "390")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("CSRFToken", csrfToken)
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// write dynamic hidden fields if found
	if formFields.hiddenField1 != "" {
		err = formWriter.WriteField(formFields.hiddenField1, "")
		if err != nil {
			return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
		}
	}

	if formFields.hiddenField2 != "" {
		err = formWriter.WriteField(formFields.hiddenField2, "")
		if err != nil {
			return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
		}
	}

	err = formWriter.WriteField("hidden_certificate_process_control", "1")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// use dynamically discovered file field name
	p12W, err := formWriter.CreateFormFile(formFields.fileField, "certkey.p12")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	_, err = io.Copy(p12W, bytes.NewReader(p12))
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// use dynamically discovered password field name
	err = formWriter.WriteField(formFields.passwordField, "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("hidden_cert_import_password", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.Close()
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to close form (%w)", err)
	}

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), &formDataBuffer)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	_, _ = io.Copy(io.Discard, resp.Body)

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: post of new certificate failed (status code %d)", resp.StatusCode)
	}

	// normally the webUI would show a waiting screen for ~7 seconds. insert
	// a delay here to account for any processing the device might do
	// before next steps
	time.Sleep(10 * time.Second)

	// get new cert ID list
	newCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}

	// find ID that is in new list but not in old (this is the new one)
	newId := ""
	countNew := 0
	for i := range newCertIDs {
		found := false

		// check if existed originally
		for j := range origCertIDs {
			if newCertIDs[i] == origCertIDs[j] {
				found = true
				break
			}
		}

		if !found {
			newId = newCertIDs[i]
			countNew++
		}
	}

	// if more than one new, can't determine which was uploaded by this app
	if countNew > 1 {
		return "", errors.New("printer: upload: failed to deduce new cert's id")
	}

	return newId, nil
}
