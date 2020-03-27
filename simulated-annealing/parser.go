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
		fmt.Println("GO Error")
		return C.CString("error\n")
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
			str_out.WriteString(", \"" + key + "\": " + "\"" + value + "\"")
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
		str_out.WriteString(", \""+i+"\": \""+ r.Tags[i]+"\"")
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
			content_str = strings.Replace(content_str, "\"", "\\\"",2)
			
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
	rule := `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [PTsecurity] JS.Trojan-Downloader.Nemucod.yo HTTP POST (:Exec:)"; flow: established, to_server;  content:!"Referer|3a|"; http_header; content:"|3a 3a 3a|Exec|3a 3a 3a|http"; http_client_body; depth:40; fast_pattern; content:"|3a|//"; http_client_body; distance:0; within:4; content:".exe|3a 3a|";http_client_body; distance:0; within:100; threshold:type limit, track by_src, count 1, seconds 30; metadata: former_category TROJAN; classtype:trojan-activity; sid:2024701; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Internet, signature_severity Major, created_at 2017_09_12, malware_family Nemucod, performance_impact Moderate, updated_at 2017_09_12;)`
	c_rule := C.CString(rule)
	parsed_rule := Parser(c_rule)

	fmt.Print("parsed rule:\n", C.GoString(parsed_rule))
}