//go:build integration
// +build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dmh/internal/state"

	"github.com/stretchr/testify/require"
)

func TestDMH(t *testing.T) {
	stateFile := "integration_test_state.json"
	vaultFile := "integration_test_vault.json"
	configFile := "integration_test_config.yaml"
	clientUUID := "integration-test-client-uuid"
	requiredEnvs := map[string]string{"DMH_CONFIG_FILE": configFile}

	getActionsInterval = 1
	getActionsIntervalUnit = time.Second

	f, err := os.Create(stateFile)
	defer os.Remove(stateFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"last_seen":"2025-03-26T14:55:40.119447+01:00","actions":[{"kind":"json_post","process_after":1,"min_interval":0,"comment":"missing-encryoption-key-from-vault","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBMUktTQjM0bFJOTDhWa05JcHdLUzM4dlBXRVQ2eklSdmdrenh4ejRJVHlJClRMWWJnZ1JaKzdTSG5QeFREZVRYdXRjWjFRa3ZLRE9ZY2NkRVo2TytrdGMKLS0tIDNoMWtzeXpiQ1JWKy9ZbHhqeHJuMjYxR2NlblZkZlIwRWRzOUJCNDZPNXcK+D+heGeg32Eym2D3wQU0evdTvRzmGvbw8cf5ukIwYyKINpu4raClZKgn5sfb4pkgqxYR+TaF4oBW3D9Jt0cZMRn5mL7pOWxDgvLMkhES3hk6U0Nfu+9SKODtipqPQubJw4gHDrw3INYjK5jVNYVcITjXzHbBMTiaZD7jNCmPH20Xrw==","uuid":"bf577b9d-26f4-4168-b8e4-0e1d692559ed","processed":0,"last_run":"0001-01-01T00:00:00Z","encryption":{"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/bf577b9d-26f4-4168-b8e4-0e1d692559ed"}},{"uuid":"9acc344e-a65b-4675-9723-5664c0e73c76","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH","process_after":1,"comment":"","processed":0, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/9acc344e-a65b-4675-9723-5664c0e73c76"}},{"uuid":"7df7c024-d0a8-4183-83fa-373ea4a7735a","kind":"json_post","data":"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBJSmIxTlBZZ1dqZlVqY2RBTjg1YjRlWEVCNjFXMFVac0EwdWczVXYxblZ3CmFPNjl5THJ6Q0ZxaGdxU2RmZlBUdXdwVjJ2ajNoSUxPSitxYStFSVBMOTQKLS0tIExpQVFsZ1p6Vy9TWVllY1NUYmt4M1BrZGV6Yk5mUkNhQURFRUhaU3BCazgKeLCm87tFZiyWy1pBgfmZnrNK/BygpARjcOz30EeA7pUnS3bAleWKsOoO+mOrYUXt4FxvS8s7botqWYvqJBU18ctHRZshxQLaz5q240EsOsBWGvxZN1rn1SonO5DsBxxrPvJJmbyI47lXpaScrnSE1eotvgt0zWDc58kkgMGgBxiMYjqQXdFylwp5WU+Q9JThCakt+QsQP9X5MRvPfPWOg9a9Kw==","process_after":10,"comment":"test","processed":2, "encryption": {"kind":"X25519","vault_url":"http://127.0.0.1:8080/api/vault/store/%s/7df7c024-d0a8-4183-83fa-373ea4a7735a"}}]}`, clientUUID, clientUUID, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(vaultFile)
	defer os.Remove(vaultFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`{"%s":{"last_seen": "2025-03-26T14:55:40.119447+01:00", "secrets": {"9acc344e-a65b-4675-9723-5664c0e73c76": {"key": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBGMDl6R0dQOGQxWUFOS21URENNRklBWVp0R2xMdzM0OGgwTDlOMmJieWxnCnJ4WS9IOUlBYmNvZDNqbm5Ua3d2R2hsemNmL2doQWZ6RjVDS0NUZ0RjTzAKLS0tIEE3UVoyYXh0MjJramFieWZab3Fmc1BSZThISGhkaTVzWmM4L1NQSUlYQ0EKcwoFDL1JXgWw0MQWaoUCRXkZJvghmbKUdDzTkXnsLWKSwvUUOMdHD+of/AUFy7MAuGQ5Pju28/Yfj/w9vAtBPCTC5mmbdTM3/0NLizGH11RZKh2dA2h1LdHRwxLxWvhhO9eBPortK0Tw+Q==", "process_after": 1, "encryption": {"kind": "X25519"}}}}}`, clientUUID))
	require.Nil(t, err)

	f, err = os.Create(configFile)
	defer os.Remove(configFile)
	require.Nil(t, err)
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf(`
    components:
      - dmh
      - vault
    vault:
      key: AGE-SECRET-KEY-1GEUMZFAZD42WGZFGATTTJHV4SURK8LU507QVCAKXKJP6UTFMJTCS0E3QJ4
      file: %s
    state:
      file: %s
    action:
      process_unit: second
    remote_vault:
      url: http://127.0.0.1:8080
      client_uuid: %s
    `, vaultFile, stateFile, clientUUID))
	require.Nil(t, err)

	for k, v := range requiredEnvs {
		err := os.Setenv(k, v)
		require.Nil(t, err)
		defer os.Unsetenv(k)
	}

	hitEndpoint := map[string]int{
		"/alive":                 0,
		"/test":                  0,
		"/action/once":           0,
		"/action/test":           0,
		"/action/min_interval":   0,
		"/action/never_executed": 0,
		"/action/missing_key":    0,
	}
	// Lets start fake server which can be used by Actions.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.Nil(t, err)

		hitEndpoint[r.URL.RequestURI()] += 1

		if r.URL.RequestURI() == "/alive" {
			require.Equal(t, `{"field1":"alive-test"}`, string(body))
			require.Equal(t, "alive", r.Header.Get("type"))
		} else if r.URL.RequestURI() == "/test" {
			require.Equal(t, `{"key1":"value1","key2":true}`, string(body))
			require.Equal(t, "test", r.Header.Get("header1"))
			require.Equal(t, "test2", r.Header.Get("header2"))
		} else if r.URL.RequestURI() == "/action/once" {
			require.Equal(t, `{"key1":"value1"}`, string(body))
		} else if r.URL.RequestURI() == "/action/test" {
			require.Equal(t, `{"key1":"value1","key2":"action/test"}`, string(body))
			require.Equal(t, "test1", r.Header.Get("header3"))
			require.Equal(t, "test2", r.Header.Get("header4"))
		} else if r.URL.RequestURI() == "/action/min_interval" {
			require.Equal(t, `{"key1":"value1","key2":"action/min_interval"}`, string(body))
			require.Equal(t, "test1", r.Header.Get("header3"))
			require.Equal(t, "test2", r.Header.Get("header4"))
		} else {
			require.FailNow(t, fmt.Sprintf("unexpected request to %s", r.URL))
		}
		w.WriteHeader(http.StatusOK)
	})
	s := httptest.NewUnstartedServer(handler)
	l, err := net.Listen("tcp", "127.0.0.1:9090")
	require.Nil(t, err)
	s.Listener = l
	s.Start()
	defer s.Close()

	go main()
	time.Sleep(1 * time.Second)

	// Lets add new alive Action
	action := &state.Action{
		Kind:         "json_post",
		ProcessAfter: 1,
		MinInterval:  4,
		Comment:      "alive",
		Data:         `{"url":"http://127.0.0.1:9090/alive","data":{"field1":"alive-test"},"headers":{"type":"alive"},"success_code":[200]}`,
	}

	actionJson, err := json.Marshal(action)
	require.Nil(t, err)

	resp, err := http.Post("http://127.0.0.1:8080/api/action/store", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets give alive probe some time to run
	time.Sleep(3 * time.Second)

	// Fetch secrets uuids we know
	for _, test := range []struct {
		inputSecretUUID string
		expectedCode    int
	}{
		{
			inputSecretUUID: "9acc344e-a65b-4675-9723-5664c0e73c76",
			expectedCode:    http.StatusNotFound,
		},
		{
			inputSecretUUID: "7df7c024-d0a8-4183-83fa-373ea4a7735a",
			expectedCode:    http.StatusNotFound,
		},
	} {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, test.inputSecretUUID))
		require.Nil(t, err)
		defer resp.Body.Close()
		require.Equal(t, test.expectedCode, resp.StatusCode)

	}

	// Lets test /api/action/test
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Data:         `{"url":"http://127.0.0.1:9090/action/test","data":{"key1":"value1", "key2": "action/test"}, "headers": {"header3": "test1", "header4": "test2"}, "success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/test", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets add new Action
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 10,
		Comment:      "comment",
		Data:         `{"url":"http://127.0.0.1:9090/action/once","data":{"key1":"value1"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/store", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets add new Action with min_interval
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 1,
		MinInterval:  4,
		Comment:      "min_interval",
		Data:         `{"url":"http://127.0.0.1:9090/action/min_interval","data":{"key1":"value1","key2":"action/min_interval"},"headers":{"header3":"test1","header4":"test2"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/store", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets wait for min_interval action to run 2x.
	time.Sleep(6 * time.Second)

	// Lets update LastSeen
	resp, err = http.Get("http://127.0.0.1:8080/api/alive")
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets add new Action
	action = &state.Action{
		Kind:         "json_post",
		ProcessAfter: 30,
		Comment:      "never_executed",
		Data:         `{"url":"http://127.0.0.1:9090/action/never_executed","data":{"key1":"value1","key2":"action/min_interval"},"headers":{"header3":"test1","header4":"test2"},"success_code":[200]}`,
	}

	actionJson, err = json.Marshal(action)
	require.Nil(t, err)

	resp, err = http.Post("http://127.0.0.1:8080/api/action/store", "application/json", bytes.NewBuffer(actionJson))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Lets fetch all actions
	var actions []*state.EncryptedAction
	resp, err = http.Get("http://127.0.0.1:8080/api/action/store")
	require.Nil(t, err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&actions)
	require.Nil(t, err)

	require.Equal(t, 7, len(actions))
	addedActionEncrypted := actions[2]
	require.NotEqual(t, action.Data, addedActionEncrypted.Data)
	require.Equal(t, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, addedActionEncrypted.UUID), addedActionEncrypted.EncryptionMeta.VaultURL)

	// Validate all actions
	for i, test := range []struct {
		expectUUID         string
		expectKind         string
		expectProcessAfter int
		expectMinInterval  int
		expectComment      string
		expectProcessed    int
	}{
		{
			expectUUID:         "bf577b9d-26f4-4168-b8e4-0e1d692559ed",
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectComment:      "missing-encryoption-key-from-vault",
			expectProcessed:    0,
		},
		{
			expectUUID:         "9acc344e-a65b-4675-9723-5664c0e73c76",
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectComment:      "",
			expectProcessed:    2,
		},
		{
			expectUUID:         "7df7c024-d0a8-4183-83fa-373ea4a7735a",
			expectKind:         "json_post",
			expectProcessAfter: 10,
			expectComment:      "test",
			expectProcessed:    2,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectMinInterval:  4,
			expectComment:      "alive",
			expectProcessed:    0,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 10,
			expectComment:      "comment",
			expectProcessed:    2,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 1,
			expectMinInterval:  4,
			expectComment:      "min_interval",
			expectProcessed:    0,
		},
		{
			expectKind:         "json_post",
			expectProcessAfter: 30,
			expectComment:      "never_executed",
			expectProcessed:    0,
		},
	} {
		if test.expectUUID != "" {
			require.Equal(t, test.expectUUID, actions[i].UUID)
		}
		require.Equal(t, test.expectKind, actions[i].Kind)
		require.Equal(t, test.expectProcessAfter, actions[i].ProcessAfter)
		require.Equal(t, test.expectMinInterval, actions[i].MinInterval)
		require.Equal(t, test.expectComment, actions[i].Comment)
		require.Equal(t, test.expectProcessed, actions[i].Processed)
	}

	// Lets check if every action has proper vault url
	for _, action := range actions {
		require.Equal(t, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), action.EncryptionMeta.VaultURL)
	}

	// Lets check that vault locked all secrets as we updated LastSeen.
	for _, action := range actions {
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID))
		require.Nil(t, err)
		defer resp.Body.Close()

		if action.Processed == 2 || action.UUID == "bf577b9d-26f4-4168-b8e4-0e1d692559ed" {
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusLocked, resp.StatusCode)
		}
	}

	// Lets fetch single action
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[1].UUID))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var encryptedAction state.EncryptedAction
	err = json.NewDecoder(resp.Body).Decode(&encryptedAction)
	require.Nil(t, err)
	require.Equal(t, "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAvb2JISGVZS3lEcmlsenlaeUFnbHRDYjJTK1FLSVdLSWkvYjhwSjRXeEg4CmxNT0YrVCtjNUZRWi9HS2d4MFFiN3AwVDlRc0k1eVJsbXBqWHhMRFhTWE0KLS0tIE12NktMSlVGVC9LMlpTRGFjZ2FRVXhpcEJjdmwyUExCL2tGaGJtZFhyc1UKfx25yewZmc6eVeuX7ufIN2vmFR/hXldbY1LW1UwNMH/AqPToZ2ZKTYdqhA7+ZtF8mOyduvsLVX1siaatb0VC4kmGdIr2DiPlVyCbcGNwTgNqjPs5RNkcqQB9DITQPfGdmGRh3OP3t16FFT91zVWDRDRVbFnSEKfeusg33wDHlsd1E99RrVPAK5TpT6wGykDCCW66Xwh8YNYkFb4s2f0PSIsE/r7bxR4mq1VNbBuV0eRo5uz9WAiR7NyH", encryptedAction.Data)
	require.Equal(t, actions[1].UUID, encryptedAction.UUID)

	// Lets delete single action
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID), nil)
	require.Nil(t, err)
	client := &http.Client{}
	resp, err = client.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Lets confirm that it was deleted
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/action/store/%s", actions[0].UUID))
	require.Nil(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Lets ensure that all fakeServer endpoints were visited
	require.Equal(t, 7, len(hitEndpoint))
	for k, v := range map[string]int{
		"/alive":                 2,
		"/test":                  1,
		"/action/once":           1,
		"/action/test":           1,
		"/action/min_interval":   2,
		"/action/never_executed": 0,
		"/action/missing_key":    0,
	} {
		require.Equal(t, v, hitEndpoint[k])
	}

	// Lets confirm vault secret lock status
	time.Sleep(3 * time.Second)

	resp, err = http.Get("http://127.0.0.1:8080/api/action/store")
	require.Nil(t, err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&actions)
	require.Nil(t, err)

	require.Equal(t, 6, len(actions))

	for _, action := range actions {
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID))
		require.Nil(t, err)
		defer resp.Body.Close()

		if action.Processed == 2 || action.UUID == "bf577b9d-26f4-4168-b8e4-0e1d692559ed" {
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
		} else if action.MinInterval > 0 {
			require.Equal(t, http.StatusOK, resp.StatusCode)
		} else if action.Processed == 0 {
			require.Equal(t, http.StatusLocked, resp.StatusCode)
		}

		if (action.Processed == 0 && action.MinInterval == 0) || action.Processed == 2 {
			req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://127.0.0.1:8080/api/vault/store/%s/%s", clientUUID, action.UUID), nil)
			require.Nil(t, err)
			resp, err = http.DefaultClient.Do(req)
			require.Nil(t, err)
			defer resp.Body.Close()
			if action.Processed == 0 {
				require.Equal(t, http.StatusLocked, resp.StatusCode)
			} else {
				require.Equal(t, http.StatusNotFound, resp.StatusCode)
			}
		}
	}

	resp, err = http.Get("http://127.0.0.1:8080/metrics")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	require.Contains(t, string(body), `dmh_actions{processed="0"} 3`)
	require.Contains(t, string(body), `dmh_actions{processed="1"} 0`)
	require.Contains(t, string(body), `dmh_actions{processed="2"} 3`)
	require.Contains(t, string(body), `dmh_action_errors_total{action="bf577b9d-26f4-4168-b8e4-0e1d692559ed",error="DecryptAction"} 10`)
}
