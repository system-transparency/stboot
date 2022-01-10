package attestation

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/state"
	"github.com/immune-gmbh/agent/v2/pkg/tcg"
)

func Enroll(ctx context.Context, client *api.Client, token string, endorsementAuth string, defaultNameHint string, anchor tcg.TrustAnchor, st *state.State) error {
	log.Info("Creating Endorsement key")
	ekHandle, ekPub, err := anchor.GetEndorsementKey()
	if err != nil {
		log.Debugf("tcg.GetEndorsementKey(glob.TpmConn): %s", err.Error())
		log.Error("Cannot create Endorsement key")
		return err
	}
	defer ekHandle.Flush(anchor)
	st.EndorsementKey = api.PublicKey(ekPub)

	log.Info("Reading Endorsement key certificate")
	ekCert, err := anchor.ReadEKCertificate()
	if err != nil {
		log.Debugf("tcg.ReadEKCertificate(glob.TpmConn): %s", err.Error())
		log.Warn("No Endorsement key certificate in NVRAM")
		st.EndorsementCertificate = nil
	} else {
		c := api.Certificate(*ekCert)
		st.EndorsementCertificate = &c
	}

	log.Info("Creating Root key")
	rootHandle, rootPub, err := anchor.CreateAndLoadRoot(endorsementAuth, "", &st.Config.Root.Public)
	if err != nil {
		log.Debugf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		log.Error("Failed to create root key")
		return err
	}
	defer rootHandle.Flush(anchor)

	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		log.Debugf("Name(rootPub): %s", err)
		log.Error("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return err
	}
	st.Root.Name = rootName

	keyCerts := make(map[string]api.Key)
	st.Keys = make(map[string]state.DeviceKeyV3)
	for keyName, keyTmpl := range st.Config.Keys {
		log.Infof("Creating '%s' key", keyName)
		keyAuth, err := tcg.GenerateAuthValue()
		if err != nil {
			log.Debugf("tcg.GenerateAuthValue(): %s", err.Error())
			log.Error("Failed to generate Auth Value")
			return err
		}
		key, priv, err := anchor.CreateAndCertifyDeviceKey(rootHandle, st.Root.Auth, keyTmpl, keyAuth)
		if err != nil {
			log.Debugf("tcg.CreateAndCertifyDeviceKey(..): %s", err.Error())
			log.Errorf("Failed to create %s key and its certification values", keyName)
			return err
		}

		st.Keys[keyName] = state.DeviceKeyV3{
			Public:     key.Public,
			Private:    priv,
			Auth:       keyAuth,
			Credential: "",
		}
		keyCerts[keyName] = key
	}

	log.Info("Certifying TPM keys")
	hostname, err := os.Hostname()
	if err != nil {
		log.Debugf("Failed to get hostname, default to %s", defaultNameHint)
		hostname = defaultNameHint
	}

	cookie, err := api.Cookie(rand.Reader)
	if err != nil {
		log.Debugf("Failed to create secure cookie: %s", err)
		log.Error("Cannot access random number generator")
		return err
	}

	var enrollReq api.Enrollment = api.Enrollment{
		NameHint:               hostname,
		Cookie:                 cookie,
		EndoresmentCertificate: st.EndorsementCertificate,
		EndoresmentKey:         st.EndorsementKey,
		Root:                   rootPub,
		Keys:                   keyCerts,
	}

	enrollResp, err := client.Enroll(ctx, token, enrollReq)
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		log.Error("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
		return err
	} else if errors.Is(err, api.FormatError) {
		log.Error("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
		return err
	} else if errors.Is(err, api.NetworkError) {
		log.Error("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return err
	} else if errors.Is(err, api.ServerError) {
		log.Error("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
		return err
	} else if err != nil {
		log.Error("Enrollment failed. An unknown error occured. Please try again later.")
		return err
	}

	if len(enrollResp) != len(enrollReq.Keys) {
		log.Debugf("No or missing credentials in server response")
		log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
		return fmt.Errorf("no credentials field")
	}

	keyCreds := make(map[string]string)
	for _, encCred := range enrollResp {
		key, ok := st.Keys[encCred.Name]
		if !ok {
			log.Debugf("Got encrypted credential for unknown key %s", encCred.Name)
			log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
			return fmt.Errorf("unknown key")
		}

		handle, err := anchor.LoadDeviceKey(rootHandle, st.Root.Auth, key.Public, key.Private)
		if err != nil {
			log.Debugf("tcg.LoadDeviceKey(..): %s", err)
			log.Errorf("Cannot load %s key.", encCred.Name)
			return err
		}

		cred, err := anchor.ActivateDeviceKey(*encCred, endorsementAuth, key.Auth, handle, ekHandle, st)
		handle.Flush(anchor)
		if err != nil {
			log.Debugf("tcg.ActivateDeviceKey(..): %s", err)
			log.Errorf("Cannot active %s key.", encCred.Name)
			return err
		}

		keyCreds[encCred.Name] = cred
	}

	if len(keyCreds) != len(st.Keys) {
		log.Warnf("Failed to active all keys. Got credentials for %d keys but requested %d.", len(keyCreds), len(st.Keys))

		if _, ok := keyCerts["aik"]; !ok {
			log.Errorf("Server refused to certify attestation key.")
			return fmt.Errorf("no aik credential")
		}
	}

	for keyName, keyCred := range keyCreds {
		key := st.Keys[keyName]
		key.Credential = keyCred
		st.Keys[keyName] = key
	}

	return nil
}
