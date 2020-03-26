package main

import ("C"
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
	str_out.WriteString("\"msg\": \""+r.Description+"\", ")
	
	if r.Flowbits != nil {
		str_out.WriteString("\"flowbits\": [")
		for i := range r.Flowbits{
			aux_flowbits := strings.Split(r.Flowbits[i].String(), ":")
			str_out.WriteString("\"" + aux_flowbits[1][:len(aux_flowbits[1])-1]+"\"")
			if i != len(r.Flowbits)-1{
				str_out.WriteString(", ")
			}
			//fmt.Println(r.Flowbits[i])
		}
		str_out.WriteString("]")
	}

	for i := range r.Matchers{
		if !strings.Contains(fmt.Sprintf("%s",r.Matchers[i]), "content"){
			aux_matchers := strings.Split(r.Matchers[i].String(), ":")
			str_out.WriteString("\"" + aux_matchers[0] + "\": " + "\"" + aux_matchers[1] + "\"")
			if i != len(r.Matchers)-1{
				str_out.WriteString(", ")
			}
			fmt.Println(aux_matchers)
		}
	}
	
	fmt.Println(str_out.String())
	return C.CString("\n")


	for i := range r.Statements{
		str_out.WriteString(r.Statements[i]+"\n")
		//fmt.Println(r.Statements[i])
	}

	for i := range r.Tags{
		str_out.WriteString(i+": "+ r.Tags[i]+"\n")
		//fmt.Println(i+":", r.Tags[i])
	}
	
	//fmt.Println(r.StreamMatch)
	if r.StreamMatch != nil{
		str_out.WriteString(r.StreamMatch.String()+"\n")
	}
	
	for i := range r.Contents(){
		str_out.WriteString(r.Contents()[i].String()+"\n")
		str_out.WriteString(r.Contents()[i].DataPosition.String()+"\n")
		//fmt.Println(r.Contents()[i])
		//fmt.Println(r.Contents()[i].DataPosition)
	}

	for i := range r.References{
		str_out.WriteString(r.References[i].String()+"\n")
		//fmt.Println(r.References[i])
	}

	str_out.WriteString(r.Metas.String()+"\n")
	str_rev := fmt.Sprintf("%d", r.Revision)
	str_sid := fmt.Sprintf("%d", r.SID)
	str_out.WriteString("rev: "+str_rev+"\n")
	str_out.WriteString("sid: "+str_sid+"\n")

	//fmt.Println(r.Metas.String())
	//fmt.Println("rev:",r.Revision)
	//fmt.Println("sid:",r.SID)

	//fmt.Print(r.Contents()[0].DataPosition)
	return C.CString(str_out.String())
}

func main() {
	rule := `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Win32.Magania"; flow: established,to_server; flowbits:set,EXE2; flowbits:noalert; content:"GET"; http_method; content:".txt"; http_uri; content:"EXE2"; depth:4; fast_pattern; nocase; http_user_agent; content:!"Accept|3a| "; nocase; http_header; content:!"Referer|3a| "; nocase; http_header; content:!"Connection|3a| "; nocase; http_header; metadata: former_category ADWARE_PUP; reference:md5,112c6db4fb8a9aa18d0cc105662af5a4; classtype:trojan-activity; sid:2018050; rev:5; metadata:created_at 2014_01_31, updated_at 2014_01_31;)`
	c_rule := C.CString(rule)
	parsed_rule := Parser(c_rule)

	fmt.Print("parsed rule:", C.GoString(parsed_rule))
}