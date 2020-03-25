package main

import ("C"
	"strings"
	"fmt"
	"github.com/google/gonids"
)

//export Parser
func Parser(crule *C.char) *C.char {
	rule := C.GoString(crule)

	r, err := gonids.ParseRule(rule)
    if err != nil {
		fmt.Println("GO Error")
    // Handle parse error
	}

	var str_out strings.Builder

	str_out.WriteString(r.Action+"\n")
	str_out.WriteString(r.Protocol+"\n")
	str_out.WriteString(r.Source.String()+"\n")
	str_out.WriteString(r.Destination.String()+"\n")
	str_out.WriteString("msg:\""+r.Description+"\""+"\n")

	for i := range r.Flowbits{
		str_out.WriteString(r.Flowbits[i].String()+"\n")
		//fmt.Println(r.Flowbits[i])
	}

	for i := range r.Matchers{
		if !strings.Contains(fmt.Sprintf("%s",r.Matchers[i]), "content"){
			str_out.WriteString(r.Matchers[i].String()+"\n")
			//fmt.Println(r.Matchers[i])
		}
	}
	
	for i := range r.Statements{
		str_out.WriteString(r.Statements[i]+"\n")
		//fmt.Println(r.Statements[i])
	}

	for i := range r.Tags{
		str_out.WriteString(i+": "+ r.Tags[i]+"\n")
		//fmt.Println(i+":", r.Tags[i])
	}
	
	fmt.Println(r.StreamMatch)
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
	//rule := `alert tcp $HOME_NET any -> $EXTERNAL_NET !$HTTP_PORTS (msg:"ET TROJAN [PTsecurity] pkt checker 0"; flow:established, to_server; dsize:200<>513; stream_size:client,>,0; stream_size:server,=,1; stream_size:client, <,513; flowbits:noalert; flowbits:set,FB180732_0; metadata: former_category TROJAN; classtype:trojan-activity; sid:2024694; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, signature_severity Major, created_at 2017_09_11, malware_family Remcos, performance_impact Moderate, updated_at 2017_09_11;)`
	
	//parsed_rule := Parser(rule)

	//fmt.Print("parsed rule:", parsed_rule)
}