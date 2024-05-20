package gelements

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/elementsproject/glightning/gbitcoin"
	"github.com/elementsproject/glightning/jrpc2"
)

// taken from bitcoind
const defaultClientTimeout int = 900
const defaultRpcHost string = "http://localhost"

const debug bool = false

func isDebug() bool {
	return debug
}

type Elements struct {
	isUp           bool
	httpClient     *http.Client
	port           uint
	host           string
	requestCounter int64
	username       string
	password       string
	rpcWallet      string

	CookiePath          string
	cookieLastCheckTime time.Time
	cookieLastModTime   time.Time
	cookieLastUser      string
	cookieLastPass      string
}

func NewElements(username, password, cookiePath string) *Elements {
	bt := &Elements{}

	tr := &http.Transport{
		MaxIdleConns:    20,
		IdleConnTimeout: time.Duration(defaultClientTimeout) * time.Second,
	}
	bt.httpClient = &http.Client{Transport: tr}
	bt.username = username
	bt.password = password
	bt.rpcWallet = ""
	bt.username = username
	bt.password = password
	bt.CookiePath = cookiePath
	return bt
}
func (b *Elements) Endpoint() string {
	endpoint := b.host + ":" + strconv.Itoa(int(b.port)) + "/wallet/" + b.rpcWallet
	return endpoint
}

func (b *Elements) SetRpcWallet(rpcWallet string) {
	b.rpcWallet = rpcWallet
}

func (b *Elements) SetTimeout(secs uint) {
	tr := &http.Transport{
		MaxIdleConns:    20,
		IdleConnTimeout: time.Duration(secs) * time.Second,
	}
	b.httpClient = &http.Client{Transport: tr}
}

func (e *Elements) getAuth() (username, passphrase string, err error) {
	// Try username+passphrase auth first.
	if e.password != "" {
		return e.username, e.password, nil
	}

	// If no username or passphrase is set, try cookie auth.
	return e.retrieveCookie()
}

// retrieveCookie returns the cookie username and passphrase.
func (e *Elements) retrieveCookie() (username, passphrase string, err error) {
	if !e.cookieLastCheckTime.IsZero() && time.Now().Before(e.cookieLastCheckTime.Add(30*time.Second)) {
		return e.cookieLastUser, e.cookieLastPass, nil
	}

	e.cookieLastCheckTime = time.Now()

	st, err := os.Stat(e.CookiePath)
	if err != nil {
		return e.cookieLastUser, e.cookieLastPass, err
	}

	modTime := st.ModTime()
	if !modTime.Equal(e.cookieLastModTime) {
		e.cookieLastModTime = modTime
		return gbitcoin.ReadCookieFile(e.CookiePath)
	}

	return e.cookieLastUser, e.cookieLastPass, nil
}

func (e *Elements) StartUp(host string, port uint) error {
	if host == "" {
		e.host = defaultRpcHost
	} else {
		e.host = host
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	e.port = port
	var lastErr error
	for {
		select {
		case _ = <-ctx.Done():
			return errors.New(fmt.Sprintf("Timeout, lastErr %v", lastErr))
		default:
			err := e.Echo()
			if err == nil {
				return nil
			}
			if err != nil {
				return err
			}
			if isDebug() {
				log.Println(err)
			}
		}
	}
}

// Blocking!
func (b *Elements) request(m jrpc2.Method, resp interface{}) error {
	id := b.NextId()
	mr := &jrpc2.Request{Id: id, Method: m}
	jbytes, err := json.Marshal(mr)
	if err != nil {
		return err
	}
	if _, ok := os.LookupEnv("GOLIGHT_DEBUG_IO"); ok {
		log.Println(string(jbytes))
	}
	req, err := http.NewRequest("POST", b.Endpoint(), bytes.NewBuffer(jbytes))
	if err != nil {
		return err
	}

	req.Header.Set("Host", b.host)
	req.Header.Set("Connection", "close")
	req.SetBasicAuth(b.username, b.password)
	req.Header.Set("Content-Type", "application/json")

	rezp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer rezp.Body.Close()

	switch rezp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("Authorization failed: Incorrect user or password")
	case http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError:
		// do nothing
	default:
		if rezp.StatusCode > http.StatusBadRequest {
			return errors.New(fmt.Sprintf("server returned HTTP error %d", rezp.StatusCode))
		} else if rezp.ContentLength == 0 {
			return errors.New("no response from server")
		}
	}

	var rawResp jrpc2.RawResponse
	if _, ok := os.LookupEnv("GOLIGHT_DEBUG_IO"); ok {
		data, err := ioutil.ReadAll(rezp.Body)
		if err != nil {
			log.Printf("err response, %s", err)
			return err
		}
		log.Println(string(data))
		err = json.Unmarshal(data, &rawResp)
	} else {
		decoder := json.NewDecoder(rezp.Body)
		err = decoder.Decode(&rawResp)
	}

	if err != nil {
		return err
	}

	if rawResp.Error != nil {
		return rawResp.Error
	}

	return json.Unmarshal(rawResp.Raw, resp)
}

type PingRequest struct{}

func (r *PingRequest) Name() string {
	return "ping"
}

func (b *Elements) Ping() (bool, error) {
	var result string
	err := b.request(&PingRequest{}, &result)
	return err == nil, err
}

type EchoRequest struct {
}

func (r *EchoRequest) Name() string {
	return "echo"
}

func (b *Elements) Echo() error {
	var result interface{}
	err := b.request(&EchoRequest{}, &result)
	return err
}

type GetBlockChainInfoRequest struct{}

func (r *GetBlockChainInfoRequest) Name() string {
	return "getblockchaininfo"
}

type ChainInfo struct {
	Chain                string               `json:"chain"`
	Blocks               uint32               `json:"blocks"`
	Headers              uint32               `json:"headers"`
	BestBlockHash        string               `json:"bestblockhash"`
	Difficulty           float64              `json:"difficulty"`
	MedianTime           uint64               `json:"mediantime"`
	VerificationProgress float64              `json:"verificationprogress"`
	InitialBlockDownload bool                 `json:"initialblockdownload"`
	ChainWork            string               `json:"chainwork"`
	SizeOnDisk           uint64               `json:"size_on_disk"`
	Pruned               bool                 `json:"pruned"`
	SoftForks            []*Fork              `json:"softforks"`
	Bip9SoftForks        map[string]*Bip9Fork `json:"softforks"`
	Warnings             string               `json:"warnings"`
}

type Fork struct {
	Id      string     `json:"id"`
	Version uint       `json:"version"`
	Reject  *RejectObj `json:"reject"`
}

type RejectObj struct {
	Status bool `json:"status"`
}

type Bip9Fork struct {
	// defined, started, locked_in, active, failed, ??
	Status      string     `json:"status"`
	StartTime   int        `json:"start_time"`
	Timeout     uint64     `json:"timeout"`
	SinceHeight uint32     `json:"since"`
	Statistics  *Bip9Stats `json:"statistics,omitempty"`
}

type Bip9Stats struct {
	Period    uint32 `json:"period"`
	Threshold uint32 `json:"threshold"`
	Elapsed   uint32 `json:"elapsed"`
	Count     uint32 `json:"count"`
	Possible  bool   `json:"possible"`
}

func (b *Elements) GetChainInfo() (*ChainInfo, error) {
	var result ChainInfo
	err := b.request(&GetBlockChainInfoRequest{}, &result)
	return &result, err
}

type GetBlockHashRequest struct {
	BlockHeight uint32 `json:"height"`
}

func (r *GetBlockHashRequest) Name() string {
	return "getblockhash"
}

func (b *Elements) GetBlockHash(height uint32) (string, error) {
	var result string
	err := b.request(&GetBlockHashRequest{height}, &result)
	return result, err
}

type GetBlockHeaderRequest struct {
	BlockHash string `json:"blockhash"`
}

type BlockVerbosity uint16

// FIXME: support options other than just raw block data
const (
	RawBlock BlockVerbosity = iota
	Json_TxId
	Json_TxData
)

type GetBlockRequest struct {
	BlockHash string `json:"blockhash"`
	// valid options: 0,1,2
	Verbosity BlockVerbosity `json:"verbosity"`
}

func (r *GetBlockRequest) Name() string {
	return "getblock"
}

// fetches raw block hex-string
func (b *Elements) GetRawBlock(blockhash string) (string, error) {
	var result string
	err := b.request(&GetBlockRequest{blockhash, RawBlock}, &result)
	return result, err
}

type EstimateFeeRequest struct {
	Blocks uint32 `json:"conf_target"`
	Mode   string `json:"estimate_mode,omitempty"`
}

func (r *EstimateFeeRequest) Name() string {
	return "estimatesmartfee"
}

type FeeResponse struct {
	FeeRate float64  `json:"feerate,omitempty"`
	Errors  []string `json:"errors,omitempty"`
	Blocks  uint32   `json:"blocks"`
}

func (fr *FeeResponse) SatPerKb() uint64 {
	return ConvertBtc(fr.FeeRate)
}

func (b *Elements) EstimateFee(blocks uint32, mode string) (*FeeResponse, error) {
	var result FeeResponse
	err := b.request(&EstimateFeeRequest{blocks, mode}, &result)
	return &result, err
}

type GetTxOutRequest struct {
	TxId           string `json:"txid"`
	Vout           uint32 `json:"n"`
	IncludeMempool bool   `json:"include_mempool"`
}

func (r *GetTxOutRequest) Name() string {
	return "gettxout"
}

type TxOutResp struct {
	BestBlockHash string     `json:"bestblock"`
	Confirmations uint32     `json:"confirmations"`
	Value         float64    `json:"value"`
	ScriptPubKey  *OutScript `json:"scriptPubKey"`
	Coinbase      bool       `json:"coinbase"`
}

func (b *Elements) GetTxOut(txid string, vout uint32) (*TxOutResp, error) {
	var result TxOutResp
	err := b.request(&GetTxOutRequest{txid, vout, true}, &result)

	// return a nil rather than an empty
	if result == (TxOutResp{}) {
		return nil, err
	}

	return &result, err
}

type GetNewAddressRequest struct {
	Label       string `json:"label,omitempty"`
	AddressType string `json:"address_type,omitempty"`
}

type AddrType int

const (
	Bech32 AddrType = iota
	P2shSegwit
	Legacy
	Blech32
)

func (a AddrType) String() string {
	return []string{"bech32", "p2sh-segwit", "legacy", "blech32"}[a]
}

func (r *GetNewAddressRequest) Name() string {
	return "getnewaddress"
}

func (b *Elements) GetNewAddress(addrType int) (string, error) {
	var result string
	err := b.request(&GetNewAddressRequest{
		AddressType: AddrType(addrType).String(),
	}, &result)
	return result, err
}

type GenerateToAddrRequest struct {
	NumBlocks uint   `json:"nblocks"`
	Address   string `json:"address"`
	MaxTries  uint   `json:"maxtries,omitempty"`
}

func (r *GenerateToAddrRequest) Name() string {
	return "generatetoaddress"
}

func (b *Elements) GenerateToAddress(address string, numBlocks uint) ([]string, error) {
	var resp []string
	err := b.request(&GenerateToAddrRequest{
		Address:   address,
		NumBlocks: numBlocks,
	}, &resp)
	return resp, err
}

type SendToAddrReq struct {
	Address               string `json:"address"`
	Amount                string `json:"amount"`
	Comment               string `json:"comment,omitempty"`
	CommentTo             string `json:"comment_to,omitempty"`
	SubtractFeeFromAmount bool   `json:"subtractfeefromamount,omitempty"`
	Replaceable           bool   `json:"replaceable,omitempty"`
	ConfirmationTarget    uint   `json:"conf_target,omitempty"`
	FeeEstimateMode       string `json:"estimate_mode,omitempty"`
	AssetLabel            string `json:"assetlabel"`
}

func (r *SendToAddrReq) Name() string {
	return "sendtoaddress"
}

func (b *Elements) SendToAddress(address, amount string) (string, error) {
	var result string
	err := b.request(&SendToAddrReq{
		Address: address,
		Amount:  amount,
	}, &result)
	return result, err
}
func (b *Elements) SendToAddressCustom(req *SendToAddrReq) (string, error) {
	var result string
	err := b.request(req, &result)
	return result, err
}

type TxIn struct {
	TxId     string `json:"txid"`
	Vout     uint   `json:"vout"`
	Sequence uint   `json:"sequence,omitempty"`
}

type TxOut struct {
	Address string
	Satoshi uint64
}

func (o *TxOut) Marshal() []byte {
	// we need to convert the satoshi into bitcoin
	// FIXME: check uint64 to float64 conversion
	amt := float64(o.Satoshi) / math.Pow(10, 8)
	log.Printf(`{"%s":"%f"`, o.Address, amt)
	return []byte(fmt.Sprintf(`{"%s":"%f"}`, o.Address, amt))
}

// Because we're using a weird JSON marshaler for parameter packing
// we encode the outputs before passing them along as a request (instead
// of writing a custom json Marshaler)
func stringifyOutputs(outs []*TxOut) []json.RawMessage {
	results := make([]json.RawMessage, len(outs))

	for i := 0; i < len(outs); i++ {
		results[i] = json.RawMessage(outs[i].Marshal())
	}

	return results
}

type CreateRawTransactionReq struct {
	Ins         []*TxIn           `json:"inputs"`
	Outs        []json.RawMessage `json:"outputs"`
	Locktime    *uint32           `json:"locktime,omitempty"`
	Replaceable *bool             `json:"replaceable,omitempty"`
}

func (r *CreateRawTransactionReq) Name() string {
	return "createrawtransaction"
}

func (b *Elements) CreateRawTx(ins []*TxIn, outs []*TxOut, locktime *uint32, replaceable *bool) (string, error) {
	if len(outs) == 0 {
		return "", errors.New("Must provide at least one output")
	}

	// bitcoind requires at least an empty array
	if ins == nil {
		ins = make([]*TxIn, 0)
	}
	request := &CreateRawTransactionReq{
		Ins:         ins,
		Outs:        stringifyOutputs(outs),
		Locktime:    locktime,
		Replaceable: replaceable,
	}

	var resp string
	err := b.request(request, &resp)
	return resp, err
}

type FundRawOptions struct {
	ChangeAddress   string `json:"changeAddress,omitempty"`
	ChangePosition  *uint  `json:"changePosition,omitempty"`
	ChangeType      string `json:"change_type,omitempty"`
	IncludeWatching *bool  `json:"includeWatching,omitempty"`
	LockUnspents    *bool  `json:"lockUnspents,omitempty"`
	FeeRate         string `json:"feeRate,omitempty"`
	// The fee will be equally deducted from the amount of each specified output.
	// Those recipients will receive less bitcoins than you enter in their
	//   corresponding amount field.
	// If no outputs are specified here, the sender pays the fee.
	// array values: The zero-based output index to deduct fee from,
	//   before a change output is added.
	SubtractFeeFromOutputs []uint `json:"subtractFeeFromOutputs,omitempty"`
	Replaceable            *bool  `json:"replaceable,omitempty"`
	ConfirmationTarget     uint   `json:"conf_target,omitempty"`
	EstimateMode           string `json:"estimate_mode,omitempty"`
}

type FundRawTransactionReq struct {
	TxString  string          `json:"hexstring"`
	Options   *FundRawOptions `json:"options,omitempty"`
	IsWitness *bool           `json:"iswitness,omitempty"`
}

func (r *FundRawTransactionReq) Name() string {
	return "fundrawtransaction"
}

type FundRawResult struct {
	TxString string  `json:"hex"`
	Fee      float64 `json:"fee"`
	// Position of the added change output, or -1
	ChangePosition int `json:"chanepos"`
}

func (f *FundRawResult) HasChange() bool {
	return f.ChangePosition != -1
}

// Defaults to a segwit transaction
func (b *Elements) FundRawTx(txstring string) (*FundRawResult, error) {
	return b.FundRawWithOptions(txstring, nil, nil)
}

func (b *Elements) FundRawWithOptions(txstring string, options *FundRawOptions, iswitness *bool) (*FundRawResult, error) {
	var resp FundRawResult
	err := b.request(&FundRawTransactionReq{
		TxString:  txstring,
		Options:   options,
		IsWitness: iswitness,
	}, &resp)
	return &resp, err
}

type SendRawTransactionReq struct {
	TxString      string `json:"hexstring"`
	AllowHighFees *bool  `json:"allowhighfees,omitempty"`
}

func (r *SendRawTransactionReq) Name() string {
	return "sendrawtransaction"
}

func (b *Elements) SendRawTx(txstring string) (string, error) {
	var result string
	err := b.request(&SendRawTransactionReq{
		TxString: txstring,
	}, &result)
	return result, err
}

type DecodeRawTransactionReq struct {
	TxString  string `json:"hexstring"`
	IsWitness *bool  `json:"iswitness,omitempty"`
}

func (r *DecodeRawTransactionReq) Name() string {
	return "decoderawtransaction"
}

type Tx struct {
	TxId        string      `json:"txid"`
	Hash        string      `json:"hash"`
	Size        uint        `json:"size"`
	VirtualSize uint        `json:"vsize"`
	Weight      uint        `json:"weight"`
	Version     uint        `json:"version"`
	Locktime    uint32      `json:"locktime"`
	Inputs      []*TxInput  `json:"vin"`
	Outputs     []*TxOutput `json:"vout"`
}

type TxInput struct {
	TxId            string   `json:"txid"`
	Vout            uint     `json:"vout"`
	ScriptSignature *Script  `json:"scriptSig"`
	TxInWitness     []string `json:"txinwitness,omitempty"`
	Sequence        uint     `json:"sequence"`
}

type Script struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

type TxOutput struct {
	// The value in BTC
	Value        float64    `json:"value"`
	Index        uint       `json:"n"`
	ScriptPubKey *OutScript `json:"scriptPubKey"`
}

type OutScript struct {
	Script
	RequiredSigs uint     `json:"reqSigs"`
	Type         string   `json:"type"`
	Addresses    []string `json:"addresses"`
}

func (tx *Tx) FindOutputIndex(address string) (uint32, error) {
	for i := 0; i < len(tx.Outputs); i++ {
		out := tx.Outputs[i]
		if out.ScriptPubKey == nil {
			continue
		}
		for j := 0; j < len(out.ScriptPubKey.Addresses); j++ {
			if out.ScriptPubKey.Addresses[j] == address {
				return uint32(i), nil
			}
		}
	}

	return 0, errors.New(fmt.Sprintf("%s not found", address))
}

func (b *Elements) DecodeRawTx(txstring string) (*Tx, error) {
	var resp Tx
	err := b.request(&DecodeRawTransactionReq{
		TxString: txstring,
	}, &resp)

	return &resp, err
}

type CreateWalletReq struct {
	WalletName string `json:"wallet_name"`
}

func (r *CreateWalletReq) Name() string {
	return "createwallet"
}

type WalletRes struct {
	WalletName string `json:"name"`
	Warning    string `json:"warning"`
}

func (b *Elements) CreateWallet(walletName string) (string, error) {
	var resp WalletRes
	err := b.request(&CreateWalletReq{
		WalletName: walletName,
	}, &resp)
	return resp.WalletName, err

}

type LoadWalletReq struct {
	FileName      string `json:"filename"`
	LoadOnStartup bool   `json:"load_on_startup"`
}

func (r *LoadWalletReq) Name() string {
	return "loadwallet"
}

func (b *Elements) LoadWallet(fileName string, loadOnStartup bool) (string, error) {
	var resp WalletRes
	err := b.request(&LoadWalletReq{
		FileName:      fileName,
		LoadOnStartup: loadOnStartup,
	}, &resp)
	return resp.WalletName, err
}

type ListWalletsReq struct{}

func (l *ListWalletsReq) Name() string {
	return "listwallets"
}

func (b *Elements) ListWallets() ([]string, error) {
	var res []string
	err := b.request(&ListWalletsReq{}, &res)
	return res, err
}

type GetRawTransactionReq struct {
	TxId      string `json:"txid"`
	Blockhash string `json:"blockhash,omitempty"`
}

func (r *GetRawTransactionReq) Name() string {
	return "getrawtransaction"
}

func (b *Elements) GetRawtransaction(txId string) (string, error) {
	var resp string
	err := b.request(&GetRawTransactionReq{TxId: txId}, &resp)
	return resp, err
}
func (b *Elements) GetRawtransactionWithBlockHash(txId string, blockHash string) (string, error) {
	var resp string
	err := b.request(&GetRawTransactionReq{TxId: txId, Blockhash: blockHash}, &resp)
	return resp, err
}

type GetBlockCountReq struct{}

func (r *GetBlockCountReq) Name() string {
	return "getblockcount"
}

func (b *Elements) GetBlockHeight() (uint64, error) {
	var resp uint64
	err := b.request(&GetBlockCountReq{}, &resp)
	return resp, err
}

type GetBlockHeaderReq struct {
	BlockHash string
	Verbose   bool
}

func (r *GetBlockHeaderReq) Name() string {
	return "getblockheader"
}

type GetBlockHeaderRes struct {
	Hash              string  `json:"hash"`
	Confirmations     uint32  `json:"confirmations"`
	Height            uint32  `json:"height"`
	Version           uint32  `json:"version"`
	VersionHex        string  `json:"versionHex"`
	Merkleroot        string  `json:"merkleroot"`
	Time              uint64  `json:"time"`
	Mediantime        uint64  `json:"mediantime"`
	Nonce             uint32  `json:"nonce"`
	Bits              string  `json:"bits"`
	Difficulty        float64 `json:"difficulty"`
	Chainwork         string  `json:"chainwork"`
	NTx               uint32  `json:"nTx"`
	Previousblockhash string  `json:"previousblockhash"`
	Nextblockhash     string  `json:"nextblockhash"`
}

func (b *Elements) GetBlockHeader(blockHash string) (*GetBlockHeaderRes, error) {
	var result GetBlockHeaderRes
	err := b.request(&GetBlockHeaderReq{blockHash, true}, &result)

	// return a nil rather than an empty
	if result == (GetBlockHeaderRes{}) {
		return nil, err
	}

	return &result, err
}

type GetBalanceRequest struct {
}

func (r *GetBalanceRequest) Name() string {
	return "getbalance"
}

type GetBalanceRes struct {
	BitcoinAmt float64 `json:"bitcoin"`
}

// GetBalance returns balance in sats
func (b *Elements) GetBalance() (uint64, error) {
	var balance GetBalanceRes
	err := b.request(&GetBalanceRequest{}, &balance)

	return ConvertBtc(balance.BitcoinAmt), err
}

type DumpBlindingKeyReq struct {
	Address string `json:"address"`
}

func (r *DumpBlindingKeyReq) Name() string {
	return "dumpblindingkey"
}

func (b *Elements) DumpBlindingKey(address string) (string, error) {
	var resp string
	err := b.request(&DumpBlindingKeyReq{Address: address}, &resp)
	return resp, err
}

type ImportAddressReq struct {
	Address string `json:"address"`
	Label   string `json:"label"`
	Rescan  bool   `json:"rescan"`
}

func (r *ImportAddressReq) Name() string {
	return "importaddress"
}

type SignRawTransactionWithWalletReq struct {
	HexString string `json:"hexstring"`
}

type SignRawTransactionWithWalletRes struct {
	Hex      string    `json:"hex"`
	Complete bool      `json:"complete"`
	Errors   []TxError `json:"errors"`
	Warning  string    `json:"warning"`
}

type TxError struct {
	TxId      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ScriptSig string `json:"scriptSig"`
	Sequence  uint32 `json:"sequence"`
	Error     string `json:"error"`
}

func (s *SignRawTransactionWithWalletReq) Name() string {
	return "signrawtransactionwithwallet"
}

func (b *Elements) SignRawTransactionWithWallet(hexString string) (SignRawTransactionWithWalletRes, error) {
	var res SignRawTransactionWithWalletRes
	err := b.request(&SignRawTransactionWithWalletReq{HexString: hexString}, &res)
	return res, err
}

func (b *Elements) ImportAddress(address, label string, rescan bool) error {
	var resp string
	err := b.request(&ImportAddressReq{
		Address: address,
		Label:   label,
		Rescan:  rescan,
	}, resp)
	return err
}

type UnblindRawTransactionReq struct {
	Hex string `json:"hex"`
}

func (u *UnblindRawTransactionReq) Name() string {
	return "unblindrawtransaction"
}

type UnblindRawTransactionRes struct {
	Hex string `json:"hex"`
}

func (b *Elements) UnblindRawtransaction(hex string) (string, error) {
	var res UnblindRawTransactionRes
	err := b.request(&UnblindRawTransactionReq{Hex: hex}, &res)
	return res.Hex, err
}

type WalletCreateFundedPsbtReq struct {
	Inputs  []PsbtInput  `json:"inputs"`
	Outputs []PsbtOutput `json:"outputs"`
}

type BlindRawTransactionReq struct {
	HexString string `json:"hexstring"`
}

func (b *BlindRawTransactionReq) Name() string {
	return "blindrawtransaction"
}

func (e *Elements) BlindRawTransaction(hex string) (string, error) {
	var res string
	err := e.request(&BlindRawTransactionReq{HexString: hex}, &res)
	return res, err
}

type RawBlindRawTransactionReq struct {
	HexString           string   `json:"hexstring"`
	InputAmountBlinders []string `json:"inputamountblinders"`
	InputAmounts        []uint64 `json:"inputamounts"`
	InputAssets         []string `json:"inputassets"`
	InputAssetBlinders  []string `json:"inputassetblinders"`
	IgnoreBlindFail     bool     `json:"ignoreblindfails"`
}

func (b *RawBlindRawTransactionReq) Name() string {
	return "rawblindrawtransaction"
}

func (e *Elements) RawBlindRawTransaction(hex string, inputAmountBlinders []string, inputAmounts []uint64, inputAssets []string, inputAssetBlinders []string) (string, error) {
	var res string
	err := e.request(&RawBlindRawTransactionReq{
		HexString:           hex,
		InputAmountBlinders: inputAmountBlinders,
		InputAmounts:        inputAmounts,
		InputAssets:         inputAssets,
		InputAssetBlinders:  inputAssetBlinders,
		IgnoreBlindFail:     true,
	}, &res)
	return res, err
}

type SetLabelReq struct {
	Address string `json:"address"`
	Label   string `json:"label"`
}

func (r *SetLabelReq) Name() string {
	return "setlabel"
}

func (e *Elements) SetLabel(address, label string) error {
	var res string
	return e.request(&SetLabelReq{
		Address: address,
		Label:   label,
	}, &res)
}

type PsbtInput struct {
	TxId     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	Sequence uint32 `json:"sequence"`
}

type PsbtOutput struct {
	Values map[string]float64 `json:"values"`
	Data   string             `json:"data"`
}

type WalletCreatFundedPsbtRes struct {
}
type GetNetworkInfoReq struct {
}

func (r *GetNetworkInfoReq) Name() string {
	return "getnetworkinfo"
}

type NetworkInfo struct {
	Version         int    `json:"version"`
	Subversion      string `json:"subversion"`
	ProtocolVersion int    `json:"protocolversion"`
}

func (b *Elements) GetNetworkInfo() (*NetworkInfo, error) {
	var res NetworkInfo
	err := b.request(&GetNetworkInfoReq{}, &res)
	return &res, err
}

// for now, use a counter as the id for requests
func (b *Elements) NextId() *jrpc2.Id {
	val := atomic.AddInt64(&b.requestCounter, 1)
	return jrpc2.NewIdAsInt(val)
}

func ConvertBtc(btc float64) uint64 {
	// this may need some intervention
	sat := btc * 100000000
	if sat != btc*100000000 {
		panic(fmt.Sprintf("overflowed converting %f to sat", btc))
	}
	return uint64(sat)
}
