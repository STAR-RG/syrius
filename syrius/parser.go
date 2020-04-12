package main

import (
	"C"
	"strings"
	"fmt"
	"github.com/google/gonids"
)

//export Parser
func Parser(c_rule *C.char) *C.char {
	rule := C.GoString(c_rule)
	r, err := gonids.ParseRule(rule)
    if err != nil {
		//fmt.Println("GO Error")
		return C.CString("error")
    	// Handle parse error
	}

	var str_out strings.Builder

	str_out.WriteString("{")
	str_out.WriteString("\"action\": \"" + r.Action+"\", ")
	str_out.WriteString("\"protocol\": \"" + r.Protocol+"\", ")
	str_out.WriteString("\"header\": \"" + r.Source.String())
	if r.Bidirectional {
		str_out.WriteString(" <-> ")
	} else {
		str_out.WriteString(" -> ")
	}
	
	str_out.WriteString(r.Destination.String()+"\", ")
	str_out.WriteString("\"msg\": \""+r.Description+"\"")
	
	if r.Flowbits != nil {
		str_out.WriteString(", \"flowbits\": [")
		for i := range r.Flowbits{
			aux_flowbits := strings.Split(r.Flowbits[i].String(), ":")
			str_out.WriteString("\"" + aux_flowbits[1][:len(aux_flowbits[1])-1]+"\"")
			if i != len(r.Flowbits)-1{
				str_out.WriteString(", ")
			}
		}
		str_out.WriteString("]")
	}
	
	for i := range r.Matchers{
		if !strings.Contains(fmt.Sprintf("%s",r.Matchers[i]), "content"){
			aux_matchers := strings.Split(r.Matchers[i].String(), ":")
			key := aux_matchers[0]
			value := aux_matchers[1]
			value = value[:len(value)-1]
			if strings.Contains(fmt.Sprintf("%s",r.Matchers[i]), "pcre"){
				value = strings.Replace(value, "\\", "\\\\",999)
				str_out.WriteString(", \"" + key + "\": " + value)	
			} else {
				str_out.WriteString(", \"" + key + "\": " + "\"" + value + "\"")
			}
			
		}
	}

	if r.Statements != nil {
		str_out.WriteString(", \"statements\": [")
		for i := range r.Statements{
			str_out.WriteString("\""+r.Statements[i]+"\"")
			if i != len(r.Statements)-1 {
				str_out.WriteString(", ")
			}
		}
		str_out.WriteString("]")
	}

	for i := range r.Tags{
		if i == "threshold" {
			aux_value := strings.Split(r.Tags[i], ",")
			aux_threshold := [][]string{}
			for j := range aux_value {
				aux_threshold = append(aux_threshold, strings.Split(aux_value[j], " "))
			}
			
			for j := range aux_threshold {
				if aux_threshold[j][0] == "" {
					aux_threshold[j] = aux_threshold[j][1:]
				}
			}
			str_out.WriteString(", \"" + i + "\": {")

			for j := range aux_threshold {
				if aux_threshold[j][0] == " " {
					aux_threshold[j][0] = aux_threshold[j][0][1:]
				}
				str_out.WriteString("\""+aux_threshold[j][0]+"\": \""+aux_threshold[j][1]+"\"")
				if j != len(aux_threshold) - 1 {
					str_out.WriteString(", ")
				}
			}
			str_out.WriteString("}")
		} else {
			str_out.WriteString(", \""+i+"\": \""+ r.Tags[i]+"\"")
		}
	}

	if r.StreamMatch != nil{
		aux_stream := strings.Split(r.StreamMatch.String(), ":")
		key := aux_stream[0]
		value := aux_stream[1]
		value = value[:len(value)-1]
		str_out.WriteString(", \""+key+"\": \""+value+"\"")
	}
	
	modifiers := [][]string{}
	sticky_buffers := []string{}
	if r.Contents() != nil {
		str_out.WriteString(", \"content\": [")
		for i := range r.Contents(){
			aux_content := strings.Split(r.Contents()[i].String(), ":")
			value := aux_content[1]
			content_str := strings.Split(value, ";")[0]
			content_str = strings.Replace(content_str, "\"", "",2)
			
			aux_modifiers := strings.Split(value, ";")[1:]
			
			modifiers = append(modifiers, aux_modifiers)
			str_out.WriteString("\""+content_str+"\"")
			if i != len(r.Contents())-1 {
				str_out.WriteString(", ")
			}

			sticky_buffers = append(sticky_buffers, r.Contents()[i].DataPosition.String())
		}
		str_out.WriteString("]")
	}

	if r.Contents() != nil {
		str_out.WriteString(", \"modifiers\": [")
		for i := range modifiers {
			str_out.WriteString("[")
			for j := range modifiers[i][:len(modifiers[i])-1] {
				str_out.WriteString("\""+modifiers[i][j][1:]+"\"")
				if j != len(modifiers[i])-2 {
					str_out.WriteString(", ")
				}
			}
			str_out.WriteString("]")
			if i != len(modifiers)-1 {
				str_out.WriteString(", ")
			}
		}
		str_out.WriteString("]")
	}
	
	if sticky_buffers != nil {
		str_out.WriteString(", \"sticky_buffers\": [")
		for i := range sticky_buffers {
			str_out.WriteString("\""+ sticky_buffers[i]+"\"")
			if i != len(sticky_buffers)-1{
				str_out.WriteString(", ")
			}
		}
		str_out.WriteString("]")
	}

	if r.References != nil {
		str_out.WriteString(", \"reference\": [")
		for i := range r.References{
			aux_reference := strings.Split(r.References[i].String(), ":")
			value := aux_reference[1][:len(aux_reference[1])-1]
			str_out.WriteString("\""+value+"\"")
			if i != len(r.References)-1 {
				str_out.WriteString(", ")
			}
		}
		str_out.WriteString("]")
	}

	if r.Metas != nil {
		str_out.WriteString(", \"metadata\": [")
		aux_metadata := strings.Split(r.Metas.String(), ":")
		value := aux_metadata[1][:len(aux_metadata[1])-1]
		metadata := strings.Split(value, ",")
		
		for i := range metadata {
			if string(metadata[i][0]) == " "{
				metadata[i] = metadata[i][1:]
			}
			str_out.WriteString("\""+metadata[i]+"\"")
			if i != len(metadata)-1 {
				str_out.WriteString(", ")
			}
		}
		
		str_out.WriteString("]")
	}

	
	str_out.WriteString(", \"rev\": ")
	str_rev := fmt.Sprintf("%d", r.Revision)
	str_out.WriteString(str_rev)
	
	str_out.WriteString(", \"sid\": ")	
	str_sid := fmt.Sprintf("%d", r.SID)
	str_out.WriteString(str_sid+"}\n")

	return C.CString(str_out.String())
}

func main() {
	test_rule := `alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT Fake AV Phone Scam Landing Nov 20"; flow:established,from_server; file_data; content:"<title>VIRUS WARNING"; fast_pattern; nocase; content:"onload=|22|myFunction()|22|"; nocase; content:"YOUR COMPUTER HAS BEEN BLOCKED"; nocase; content:"CALL IMMEDIATLY"; nocase; content:"|5c 6e 5c 6e 5c 6e 5c 6e 5c 6e 5c 6e 5c 6e 5c 6e 5c 6e|"; nocase; metadata: former_category WEB_CLIENT; classtype:trojan-activity; sid:2022125; rev:3; metadata:created_at 2015_11_20, updated_at 2015_11_20;)`
	c_rule := C.CString(test_rule)
	parsed_rule := Parser(c_rule)

	fmt.Print("parsed rule:\n", C.GoString(parsed_rule))
}