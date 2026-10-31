package devruntime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/kredoxi/kredoxi/internal/synthetic"
)

const maxBootstrap = 32 * 1024
const maxControl = 256

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

type ControlCommand struct {
	ID        uint64 `json:"id"`
	Operation string `json:"operation"`
}

type ControlAck struct {
	ID        uint64 `json:"id"`
	Operation string `json:"operation"`
	Applied   bool   `json:"applied"`
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

func EncodeControl(command ControlCommand) ([]byte, error) {
	if command.ID == 0 || command.Operation == "" || len(command.Operation) > 64 {
		return nil, errors.New("invalid development control")
	}
	data, err := json.Marshal(command)
	if err != nil || len(data)+1 > maxControl {
		return nil, errors.New("invalid development control")
	}
	return append(data, '\n'), nil
}

func WriteControlAck(writer io.Writer, ack ControlAck) error {
	if ack.ID == 0 || ack.Operation == "" || len(ack.Operation) > 64 {
		return errors.New("invalid development control acknowledgement")
	}
	data, err := json.Marshal(ack)
	if err != nil || len(data)+len("KREDOXI_ACK \n") > maxControl {
		return errors.New("invalid development control acknowledgement")
	}
	_, err = writer.Write(append(append([]byte("KREDOXI_ACK "), data...), '\n'))
	return err
}

func ParseControlAck(line string) (ControlAck, error) {
	var ack ControlAck
	const prefix = "KREDOXI_ACK "
	if len(line) > maxControl || len(line) <= len(prefix) || line[:len(prefix)] != prefix {
		return ack, errors.New("invalid development control acknowledgement")
	}
	data := []byte(line[len(prefix):])
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ack); err != nil || ack.ID == 0 || ack.Operation == "" ||
		len(ack.Operation) > 64 {
		return ControlAck{}, errors.New("invalid development control acknowledgement")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ControlAck{}, errors.New("invalid development control acknowledgement")
	}
	canonical, err := json.Marshal(ack)
	if err != nil || !bytes.Equal(canonical, data) {
		return ControlAck{}, errors.New("invalid development control acknowledgement")
	}
	return ack, nil
}

func ReadControl(reader *bufio.Reader) (ControlCommand, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > maxControl {
		return ControlCommand{}, errors.New("invalid development control")
	}
	data := line[:len(line)-1]
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var command ControlCommand
	if err := decoder.Decode(&command); err != nil || command.ID == 0 ||
		command.Operation == "" || len(command.Operation) > 64 {
		return ControlCommand{}, errors.New("invalid development control")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ControlCommand{}, errors.New("invalid development control")
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, data) {
		return ControlCommand{}, errors.New("invalid development control")
	}
	return command, nil
}
