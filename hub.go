package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Packet struct {
	Length  byte
	Payload interface{}
	CRC8    byte
}

type Payload struct {
	Src     uint64
	Dst     uint64
	Serial  uint64
	DevType byte
	Cmd     byte
	CmdBody interface{}
}

type CmdBodyTimer struct {
	DevName   string
	Timestamp uint64
}

type CmdBodySwitch struct {
	DevName  string
	DevProps DevPropsSwitch
}

type CmdBodyLamp struct {
	DevName string
	value   byte
}

type DevPropsSwitch struct {
	DevNames []string
	value    byte
}

type DevPropsSensor struct {
	Sensors  byte
	triggers []triggers
}

type triggers struct {
	op     byte
	values uint64
	name   string
}

type CmdBodyHub struct {
	DevName string
}

type CmdBodySensor struct {
	DevProps DevPropsSensor
	DevName  string
	values   []uint64
}

type CmdBodySocet struct {
	DevName string
	value   byte
}

func Base64URLDecode(enc string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func DecodeVarUint(data []byte) (uint64, int) {
	result := uint64(0)
	numBytes := 0

	for i := 0; i < len(data); i++ {
		byteValue := uint64(data[i])
		result |= (byteValue & 0x7F) << (7 * numBytes)
		numBytes++

		if byteValue&0x80 == 0 {
			break
		}
	}

	return result, numBytes
}

func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func EncodeVarUint(value uint64) []byte {
	var encodedBytes []byte

	for {
		byteValue := byte(value & 0x7F)
		value >>= 7

		if value > 0 {
			byteValue |= 0x80
		}

		encodedBytes = append(encodedBytes, byteValue)

		if value == 0 {
			break
		}
	}

	return encodedBytes
}

func ishere(pak *[]Packet, val uint64) (bool, Packet) {
	flag := false
	var p Packet

	for _, it := range *pak {
		if it.Payload.(*Payload).Src == val {
			flag = true
			p = it
			break
		}
	}

	return flag, p
}

func rewrire(pak *[]Packet, new_pkt *Packet, val uint64) {
	for num, it := range *pak {
		if it.Payload.(*Payload).Src == val {
			(*pak)[num] = *new_pkt
			break
		}
	}
}

func add_new_names(offset, tmp int, length byte, decoded []byte) []string {
	var last int
	var res []string
	for i := offset; i < int(length)+tmp; i++ {

		str := string(decoded[i : i+1])
		if _, err := strconv.Atoi(str); err == nil {
			res = append(res, string(decoded[i-last:i+2]))
			last = 0
			i += 2
		} else {
			last++
		}
	}
	return res
}

func add_new_name(offset, tmp int, length byte, decoded []byte) (int, string) {
	var last int
	var res string
	for i := offset; i < int(length)+tmp; i++ {

		str := string(decoded[i : i+1])
		if _, err := strconv.Atoi(str); err == nil {
			res = string(decoded[i-last : i+2])
			break
		} else {
			last++
		}
	}
	return offset, res
}

func parser(decoded []byte) []Packet {
	var packets []Packet
	offset := 0
	numBytes := 0

	for offset < len(decoded) {

		tmp := offset
		length := decoded[offset]
		offset++

		pld := &Payload{}

		pld.Src, numBytes = DecodeVarUint(decoded[offset:])
		offset += numBytes

		pld.Dst, numBytes = DecodeVarUint(decoded[offset:])
		offset += numBytes

		pld.Serial, numBytes = DecodeVarUint(decoded[offset:])
		offset += numBytes

		pld.DevType = decoded[offset]
		offset++

		pld.Cmd = decoded[offset]
		offset++

		switch pld.DevType {
		case 1:
			pld.CmdBody = &CmdBodyHub{}
			break
		case 2:
			pld.CmdBody = &CmdBodySensor{}
			break
		case 3:
			pld.CmdBody = &CmdBodySwitch{}
			break
		case 4:
			pld.CmdBody = &CmdBodyLamp{}
			break
		case 5:
			pld.CmdBody = &CmdBodySocet{}
			break
		case 6:
			pld.CmdBody = &CmdBodyTimer{}
			break
		}

		switch pld.Cmd {
		case 1:
			switch pld.DevType {
			case 1:
				numBytes, pld.CmdBody.(*CmdBodyHub).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 2:

				numBytes, pld.CmdBody.(*CmdBodySensor).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes

				pld.CmdBody.(*CmdBodySensor).DevProps.Sensors = decoded[offset+1]
				offset++

				for offset < int(length)+tmp {
					tmp_trig := &triggers{}

					tmp_trig.values, numBytes = DecodeVarUint(decoded[offset:])
					offset += numBytes

					tmp_trig.op = decoded[offset]
					offset++

					numBytes, tmp_trig.name = add_new_name(offset+1, tmp, length, decoded)
					offset += numBytes

					pld.CmdBody.(*CmdBodySensor).DevProps.triggers = append(pld.CmdBody.(*CmdBodySensor).DevProps.triggers, *tmp_trig)
				}

				break
			case 3:

				numBytes, pld.CmdBody.(*CmdBodySwitch).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes

				pld.CmdBody.(*CmdBodySwitch).DevProps.DevNames = add_new_names(offset+1, tmp, length, decoded)
				break
			case 4:
				numBytes, pld.CmdBody.(*CmdBodyLamp).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 5:
				numBytes, pld.CmdBody.(*CmdBodySocet).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 6:
				break
			}
		case 2:
			switch pld.DevType {
			case 1:
				numBytes, pld.CmdBody.(*CmdBodyHub).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 2:
				numBytes, pld.CmdBody.(*CmdBodySensor).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes

				pld.CmdBody.(*CmdBodySensor).DevProps.Sensors = decoded[offset+1]
				offset++

				for offset < int(length)+tmp {
					tmp_trig := &triggers{}

					tmp_trig.values, numBytes = DecodeVarUint(decoded[offset:])
					offset += numBytes

					tmp_trig.op = decoded[offset]
					offset++

					numBytes, tmp_trig.name = add_new_name(offset+1, tmp, length, decoded)
					offset += numBytes

					pld.CmdBody.(*CmdBodySensor).DevProps.triggers = append(pld.CmdBody.(*CmdBodySensor).DevProps.triggers, *tmp_trig)
				}

				break
			case 3:
				numBytes, pld.CmdBody.(*CmdBodySwitch).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				pld.CmdBody.(*CmdBodySwitch).DevProps.DevNames = add_new_names(offset+1, tmp, length, decoded)
				break
			case 4:
				numBytes, pld.CmdBody.(*CmdBodyLamp).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 5:
				numBytes, pld.CmdBody.(*CmdBodySocet).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			case 6:
				numBytes, pld.CmdBody.(*CmdBodyTimer).DevName = add_new_name(offset+1, tmp, length, decoded)
				offset += numBytes
				break
			}
		case 3:
			break
		case 4:
			switch pld.DevType {
			case 1:
				break
			case 2:
				pld.CmdBody.(*CmdBodySensor).DevProps.Sensors = decoded[offset]
				offset++
				for offset < int(length) {
					var temp uint64
					temp, numBytes = DecodeVarUint(decoded[offset:])
					offset += numBytes
					pld.CmdBody.(*CmdBodySensor).values = append(pld.CmdBody.(*CmdBodySensor).values, temp)
				}
				break
			case 3:
				pld.CmdBody.(*CmdBodySwitch).DevProps.value = decoded[offset]
				offset++
				break
			case 4:
				pld.CmdBody.(*CmdBodyLamp).value = decoded[offset]
				offset++
				break
			case 5:
				pld.CmdBody.(*CmdBodySocet).value = decoded[offset]
				offset++
				break
			case 6:
				break
			}
		case 5:
			switch pld.DevType {
			case 1:
				break
			case 2:
				break
			case 3:
				break
			case 4:
				pld.CmdBody.(*CmdBodyLamp).value = decoded[offset]
				offset++
				break
			case 5:
				pld.CmdBody.(*CmdBodySocet).value = decoded[offset]
				offset++
				break
			case 6:
				break
			}
		case 6:
			switch pld.DevType {
			case 6:
				pld.CmdBody.(*CmdBodyTimer).Timestamp, numBytes = DecodeVarUint(decoded[offset:])
				offset += numBytes
				break
			}
		}

		pkt := Packet{
			Length:  length,
			Payload: pld,
			CRC8:    decoded[int(length)+1+tmp],
		}

		offset = tmp
		packets = append(packets, pkt)
		offset += int(length) + 2
	}

	return packets
}

func Request(url string, message string) ([]byte, int) {
	var temp []byte

	payload := strings.NewReader(message)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return temp, 99
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return temp, 99
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return temp, 99
	}

	if resp.StatusCode == 200 {
		return responseBody, 200
	} else if resp.StatusCode == 204 {
		return temp, 204
	} else {
		return temp, 99
	}
}

var prevTime uint64
var disable map[string]bool

func Search(name string, packets *[]Packet) Packet {
	for _, it := range *packets {
		if it.Payload.(*CmdBodyLamp).DevName == name {
			return it
		}
	}
	return (*packets)[0]
}

func EncodePacket(packet Packet) string {
	payload := packet.Payload.(Payload)

	encodedPayload := make([]byte, 0)

	encodedPayload = append(encodedPayload, EncodeVarUint(payload.Src)...)
	encodedPayload = append(encodedPayload, EncodeVarUint(payload.Dst)...)
	encodedPayload = append(encodedPayload, EncodeVarUint(payload.Serial)...)

	encodedPacket := []byte{packet.Length}
	encodedPacket = append(encodedPacket, encodedPayload...)
	encodedPacket = append(encodedPacket, packet.CRC8)

	return Base64URLEncode(encodedPacket)
}

func sendDataToServer(data []byte, url string) error {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") == "application/json" {

	}

	return nil
}

func stringToBytes(str string) []byte {
	bytes := []byte(str)
	return bytes
}

func handler(packets *[]Packet, url string) {
	disable := make(map[string]bool)
	prev := uint64(0)

	for _, pt := range *packets {
		if pt.Payload.(*Payload).DevType == 6 && pt.Payload.(*Payload).Cmd == 6 {
			newTime := pt.Payload.(*CmdBodyTimer).Timestamp

			if newTime-prev > 300 {
				disable[string(pt.Payload.(*Payload).Src)] = true
				prev = newTime
			} else {
				flag := disable[string(pt.Payload.(*Payload).Src)]
				if flag {
					delete(disable, string(pt.Payload.(*Payload).Src))
				}
			}
			prev = newTime
		} else if pt.Payload.(*Payload).DevType == 6 {
			time := pt.Payload.(*CmdBodyTimer).Timestamp
			_ = time
		} else if pt.Payload.(*Payload).DevType == 3 {
			if pt.Payload.(*CmdBodySwitch).DevProps.value == 1 {
				for _, it := range pt.Payload.(*CmdBodySwitch).DevProps.DevNames {

					dev := Search(it, packets)

					if dev.Payload.(*CmdBodyLamp).value == 0 {
						dev.Payload.(*CmdBodyLamp).value = 1
					}
				}
			} else {
				for _, it := range pt.Payload.(*CmdBodySwitch).DevProps.DevNames {

					dev := Search(it, packets)

					if dev.Payload.(*CmdBodyLamp).value == 1 {
						dev.Payload.(*CmdBodyLamp).value = 0
					}
				}
			}
		}
	}
	for _, it := range *packets {
		str := EncodePacket(it)
		sendDataToServer(stringToBytes(str), url)
	}
}

func rem(newData string) string {
	newData = strings.ReplaceAll(newData, " ", "")
	newData = strings.ReplaceAll(newData, "\t", "")
	newData = strings.ReplaceAll(newData, "\n", "")

	return newData
}

func main() {
	url := os.Args[1]
	_ = os.Args[2]

	disable = make(map[string]bool)
	message := ""
	i := 0

	for {
		if i == 0 {
			message = "DLMG_38BAQEEMHgwMc0"
		}

		data, code := Request(url, message)
		if code != 200 {
			if code == 204 {
				os.Exit(0)
			} else {
				os.Exit(99)
			}
		}

		newData := string(data)

		newData = rem(newData)

		decoded, err := base64.URLEncoding.DecodeString(newData)
		if err != nil {
			continue
		}

		var coden []byte

		coden, err = Base64URLDecode(string(decoded))
		if err != nil {
			continue
		}

		pack := parser(coden)

		handler(&pack, url)
		i++
	}
}
