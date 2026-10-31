package devruntime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/kredoxi/kredoxi/internal/synthetic"
)

const maxBootstrap = 32 * 1024

type BrokerBootstrap struct {
	TLS          synthetic.TLSMaterial `json:"tls"`
	Policy       []byte                `json:"policy"`
	PolicyDigest string                `json:"policy_digest"`
	Reference    string                `json:"reference"`
	Credential   string                `json:"credential"`
}

type ConsumerBootstrap struct {
	TLS            synthetic.TLSMaterial `json:"tls"`
	BrokerAddress  string                `json:"broker_address"`
	ServiceAddress string                `json:"service_address"`
}

type ServiceBootstrap struct {
	Credential string `json:"credential"`
}

func Encode(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxBootstrap {
		return nil, errors.New("invalid development bootstrap")
	}
	return append(data, '\n'), nil
}

func Decode(reader *bufio.Reader, output any) error {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > maxBootstrap {
		return errors.New("invalid development bootstrap")
	}
	data := line[:len(line)-1]
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := inspectJSON(decoder, 0); err != nil {
		return errors.New("invalid development bootstrap")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid development bootstrap")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid development bootstrap")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid development bootstrap")
	}
	return nil
}

func inspectJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("invalid development bootstrap")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if depth == 0 {
			return errors.New("invalid development bootstrap")
		}
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return errors.New("invalid development bootstrap")
			}
			if _, exists := seen[key]; exists {
				return errors.New("invalid development bootstrap")
			}
			seen[key] = struct{}{}
			if err := inspectJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := inspectJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid development bootstrap")
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != closing {
		return errors.New("invalid development bootstrap")
	}
	return nil
}

func ReadControl(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 32 {
		return "", errors.New("invalid development control")
	}
	command := strings.TrimSpace(string(line[:len(line)-1]))
	if command == "" {
		return "", errors.New("invalid development control")
	}
	return command, nil
}
