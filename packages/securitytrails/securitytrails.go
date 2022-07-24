package securitytrails

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func Find(domin string, key string) []string {

	resp, err := call(domin, "a", key)
	if err != nil {
		panic(err)
	}
	ips := aResHandler(resp)
	resp, err = call("partdp.ir", "mx", key)
	if err != nil {
		panic(err)
	}
	mailHosts := mxResHandler(resp)
	for _, host := range mailHosts {
		if host != domin {
			//fmt.Println(host)
			resp, err := call(host, "a", key)
			if err != nil {
				fmt.Println(err)
			}
			ipList := aResHandler(resp)
			ips = append(ips, ipList...)
		}
	}
	ips = RemoveDuplicateStr(ips)
	return ips
}

func call(domin string, recType string, key string) (*http.Response, error) {
	client := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/%s", domin, recType), nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Accept": {"application/json"},
		"APIKEY": {key},
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func aResHandler(resp *http.Response) []string {
	var ips []string
	var results map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	// close response body
	resp.Body.Close()
	err = json.Unmarshal(body, &results)
	if err != nil {
		fmt.Println(err)
	}
	records := results["records"].([]interface{})

	for _, j := range records {
		h := j.(map[string]interface{})
		t := h["values"].([]interface{})
		for _, v := range t {
			x := v.(map[string]interface{})
			//fmt.Println(x["ip"])
			ips = append(ips, x["ip"].(string))
		}

	}
	ips = RemoveDuplicateStr(ips)
	return ips
}
func mxResHandler(resp *http.Response) []string {
	var ips []string
	var results map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	// close response body
	resp.Body.Close()
	err = json.Unmarshal(body, &results)
	if err != nil {
		fmt.Println(err)
	}
	records := results["records"].([]interface{})

	for _, j := range records {
		h := j.(map[string]interface{})
		t := h["values"].([]interface{})
		for _, v := range t {
			x := v.(map[string]interface{})
			//fmt.Println(x["ip"])
			ips = append(ips, x["host"].(string))
		}

	}
	ips = RemoveDuplicateStr(ips)
	return ips
}

func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
