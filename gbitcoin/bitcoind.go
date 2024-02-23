package gbitcoin

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

	"github.com/elementsproject/glightning/jrpc2"
)

// taken from bitcoind
const defaultClientTimeout int = 900
const defaultRpcHost string = "http://localhost"

const debug bool = false

func isDebug() bool {
	return debug
}

type Bitcoin struct {
	isUp           bool
	httpClient     *http.Client
	port           uint
	host           string
	bitcoinDir     string
	requestCounter int64
	username       string
	password       string
}

func NewBitcoin(username, password string) *Bitcoin {
	bt := &Bitcoin{}

	tr := &http.Transport{
		MaxIdleConns:    20,
		IdleConnTimeout: time.Duration(defaultClientTimeout) * time.Second,
	}
	bt.httpClient = &http.Client{Transport: tr}
	bt.username = username
	bt.password = password
	return bt
}

func (b *Bitcoin) Endpoint() string {
	return b.host + ":" + strconv.Itoa(int(b.port))
}

func (b *Bitcoin) SetTimeout(secs uint) {
	tr := &http.Transport{
		MaxIdleConns:    20,
		IdleConnTimeout: time.Duration(secs) * time.Second,
	}
	b.httpClient = &http.Client{Transport: tr}
}

func (b *Bitcoin) StartUp(host, bitcoinDir string, port uint) error {
	if host == "" {
		b.host = defaultRpcHost
	} else {
		b.host = host
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	b.port = port
	b.bitcoinDir = bitcoinDir
	var lastErr error
	for {
		select {
		case _ = <-ctx.Done():
			return errors.New(fmt.Sprintf("Timeout, lastErr %v", lastErr))
		default:
			err := b.Echo()
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

// Request takes a raw request and issues an RPC call to bitcoind.
func (b *Bitcoin) Request(m jrpc2.Method, resp interface{}) error {
	return b.request(m, resp)
}

// Blocking!
func (b *Bitcoin) request(m jrpc2.Method, resp interface{}) error {

	id := b.NextId()
	mr := &jrpc2.Request{id, m}
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

func (b *Bitcoin) Ping() (bool, error) {
	var result string
	err := b.request(&PingRequest{}, &result)
	return err == nil, err
}

type EchoRequest struct {
}

func (r *EchoRequest) Name() string {
	return "echo"
}

func (b *Bitcoin) Echo() error {
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

func (b *Bitcoin) GetChainInfo() (*ChainInfo, error) {
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

func (b *Bitcoin) GetBlockHash(height uint32) (string, error) {
	var result string
	err := b.request(&GetBlockHashRequest{height}, &result)
	return result, err
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
func (b *Bitcoin) GetRawBlock(blockhash string) (string, error) {
	var result string
	err := b.request(&GetBlockRequest{blockhash, RawBlock}, &result)
	return result, err
}

type MempoolInfo struct {
	Loaded           bool    `json:"loaded"`
	Size             uint32  `json:"size"`
	Bytes            uint64  `json:"bytes"`
	Usage            uint32  `json:"usage"`
	MaxMempool       uint32  `json:"maxmempool"`
	MempoolMinFee    float64 `json:"mempoolminfee"`
	MinRelayTxFee    float64 `json:"minrelaytxfee"`
	UnbroadcastCount uint32  `json:"unbroadcastcount"`
}

type GetMempoolInfoReq struct{}

func (r *GetMempoolInfoReq) Name() string {
	return "getmempoolinfo"
}

func (b *Bitcoin) GetMempoolInfo() (*MempoolInfo, error) {
	var result MempoolInfo
	err := b.request(&GetMempoolInfoReq{}, &result)
	return &result, err
}

type GetRawTransactionReq struct {
	TxId      string `json:"txid"`
	Blockhash string `json:"blockhash,omitempty"`
}

func (r *GetRawTransactionReq) Name() string {
	return "getrawtransaction"
}

func (b *Bitcoin) GetRawtransaction(txId string) (string, error) {
	var resp string
	err := b.request(&GetRawTransactionReq{TxId: txId}, &resp)
	return resp, err
}
func (b *Bitcoin) GetRawtransactionWithBlockHash(txId string, blockHash string) (string, error) {
	var resp string
	err := b.request(&GetRawTransactionReq{TxId: txId, Blockhash: blockHash}, &resp)
	return resp, err
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

func (b *Bitcoin) EstimateFee(blocks uint32, mode string) (*FeeResponse, error) {
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

func (b *Bitcoin) GetTxOut(txid string, vout uint32) (*TxOutResp, error) {
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
)

func (a AddrType) String() string {
	return []string{"bech32", "p2sh-segwit", "legacy"}[a]
}

func (r *GetNewAddressRequest) Name() string {
	return "getnewaddress"
}

func (b *Bitcoin) GetNewAddress(addrType AddrType) (string, error) {
	var result string
	err := b.request(&GetNewAddressRequest{
		AddressType: addrType.String(),
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

func (b *Bitcoin) GenerateToAddress(address string, numBlocks uint) ([]string, error) {
	var resp []string
	err := b.request(&GenerateToAddrRequest{
		NumBlocks: numBlocks,
		Address:   address,
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
}

func (r *SendToAddrReq) Name() string {
	return "sendtoaddress"
}

func (b *Bitcoin) SendToAddress(address, amount string) (string, error) {
	var result string
	err := b.request(&SendToAddrReq{
		Address: address,
		Amount:  amount,
	}, &result)
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

type GetBlockCountReq struct{}

func (r *GetBlockCountReq) Name() string {
	return "getblockcount"
}

func (b *Bitcoin) GetBlockHeight() (uint64, error) {
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

func (b *Bitcoin) GetBlockHeader(blockHash string) (*GetBlockHeaderRes, error) {
	var result GetBlockHeaderRes
	err := b.request(&GetBlockHeaderReq{blockHash, true}, &result)

	// return a nil rather than an empty
	if result == (GetBlockHeaderRes{}) {
		return nil, err
	}

	return &result, err
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

func (b *Bitcoin) CreateRawTx(ins []*TxIn, outs []*TxOut, locktime *uint32, replaceable *bool) (string, error) {
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
func (b *Bitcoin) FundRawTx(txstring string) (*FundRawResult, error) {
	return b.FundRawWithOptions(txstring, nil, nil)
}

func (b *Bitcoin) FundRawWithOptions(txstring string, options *FundRawOptions, iswitness *bool) (*FundRawResult, error) {
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

func (b *Bitcoin) SendRawTx(txstring string) (string, error) {
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

func (b *Bitcoin) DecodeRawTx(txstring string) (*Tx, error) {
	var resp Tx
	err := b.request(&DecodeRawTransactionReq{
		TxString: txstring,
	}, &resp)

	return &resp, err
}

// for now, use a counter as the id for requests
func (b *Bitcoin) NextId() *jrpc2.Id {
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
