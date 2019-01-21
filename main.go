package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
)

const (
	clientString = "testing"
	clientVersion = "1.4"
)

func main(){
	fmt.Println("Proof of Concept: PoW already covers number of transactions")

	fmt.Println("Connecting to ElectrumX Server")
	// Connect to ElectrumX SV server
	socket, err := connect("sv.electrumx.cash:50001")
	if err != nil {
		panic(err)
	}
	defer socket.close()

	fmt.Println("Announcing protocol version to server")
	// Announce version
	_, _, err = socket.serverVersion(clientString, clientVersion, clientVersion)
	if err != nil {
		panic(err)
	}

	for {
		height := 0
		fmt.Print("Please enter a block height: ")

		if _, err := fmt.Scanf("%d", &height); err != nil {
			panic(err)
		}

		// Get block header
		header, err := socket.blockchainBlockHeader(height)
		if err != nil {
			panic(err)
		}

		if len(header) != 160 {
			panic("Invalid header received by server")
		}

		headerBs, err := hex.DecodeString(header)
		if err != nil {
			panic(err)
		}

		merkleRoot := headerBs[36:68]

		fmt.Printf("  Got the merkle root hash: %x\n", reverse(merkleRoot))

		for {
			txhashHex := ""

			fmt.Print("  Please enter a transaction id: ")
			if _, err := fmt.Scanf("%s", &txhashHex); err != nil {
				panic(err)
			}

			fmt.Println("    Requesting SPV (merkle tree proof)")

			merkleProofHex, pos, err := socket.blockchainTransactionGetMerkle(height, txhashHex)
			if err != nil {
				panic(err)
			}

			txhash, err := hex.DecodeString(txhashHex)
			if err != nil {
				panic(err)
			}
			txhash = reverse(txhash)

			merkleProof := make([][]byte, len(merkleProofHex))
			for i := 0; i < len(merkleProofHex); i++ {
				merkleProof[i], err = hex.DecodeString(merkleProofHex[i])
				if err != nil {
					panic(err)
				}
			}

			fmt.Printf("    The server said that the entered transaction is #%d in the block, let's better check that!\n", pos + 1)
			correct, isLast := checkProof(pos, merkleRoot, txhash, merkleProof)
			if correct {
				fmt.Printf("    Yeah, that's actually correct, this transaction is #%d in the block!\n", pos + 1)
				if pos == 0 {
					fmt.Println("    Also, the transaction is the first transaction in the block!")
				}
				if isLast {
					fmt.Println("    Also, the transaction is the last transaction in the block!")
				}
			} else {
				fmt.Println("    Looks like that's not correct, someone tries to trick us!")
			}
		}
	}
}

func checkProof(pos int, root, txhash []byte, merkle [][]byte) (correct, isLast bool) {
	state := txhash

	isLast = true
	for i := uint(0); i < uint(len(merkle)); i++ {
		if (pos >> i) % 2 == 1 {
			state = sha256dCat(reverse(merkle[i]), state)
		} else {
			if !equal(state, reverse(merkle[i])) {
				isLast = false
			}
			state = sha256dCat(state, reverse(merkle[i]))
		}
	}

	return equal(state, root), isLast
}

func equal(lhs, rhs []byte) bool {
	if len(lhs) != len(rhs) {
		panic("len doesn't match")
	}

	for i := 0; i < len(lhs); i++ {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	return true
}

func sha256dCat(lhs, rhs []byte) []byte {
	h := sha256.New()
	h.Write(lhs)
	h.Write(rhs)
	hashed := h.Sum(nil)
	bs := sha256.Sum256(hashed)
	return bs[:]
}

func reverse(s []byte) []byte {
	bs := make([]byte, len(s))
	copy(bs, s)

	for i, j := 0, len(bs)-1; i < j; i, j = i+1, j-1 {
		bs[i], bs[j] = bs[j], bs[i]
	}
	return bs
}

const jsonrpcVersion = "2.0"

type socket struct {
	conn net.Conn
}

func connect(server string) (*socket, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	return &socket{
		conn: conn,
	}, nil
}

func (s *socket) serverVersion(clientName string, protocolMin string, protocolMax string) (serverSoftwareVersion string, protocolVersion string, err error) {
	res, err := s.call("server.version", []string{protocolMin, protocolMax})
	if err != nil {
		return "", "", fmt.Errorf("call failed: %v", err)
	}

	var body []string
	if err := json.Unmarshal(res, &body); err != nil {
		return "", "", fmt.Errorf("unmarshal failed: %v", err)
	}

	if len(body) != 2 {
		return "", "", fmt.Errorf("invalid response by server: len(body) != 2")
	}

	return body[0], body[1], nil
}

func (s *socket) blockchainBlockHeader(height int) (header string, err error) {
	res, err := s.call("blockchain.block.header", map[string]int{
		"height": height,
		"cp_height": 0,
	})
	if err != nil {
		return "", fmt.Errorf("failed to call method: %v", err)
	}

	var body string
	if err := json.Unmarshal(res, &body); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return body, nil
}

func (s *socket) blockchainTransactionGetMerkle(height int, txid string) (merkle []string, pos int, err error) {
	res, err := s.call("blockchain.transaction.get_merkle", map[string]interface{}{
		"tx_hash": txid,
		"height": height,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to call method: %v", err)
	}

	var body struct {
		Merkle []string `json:"merkle"`
		Pos int `json:"pos"`
	}
	if err := json.Unmarshal(res, &body); err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return body.Merkle, body.Pos, nil
}

func (s *socket) call(method string, params interface{}) (json.RawMessage, error) {
	parambs, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal params: %v", err)
	}

	id := generateId()
	req := &request{
		Version: jsonrpcVersion,
		Method: method,
		Params: parambs,
		Identifier: id,
	}

	if err := json.NewEncoder(s.conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to encode json")
	}

	var res response
	if err := json.NewDecoder(s.conn).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode response")
	}

	if res.Error != nil {
		return nil, res.Error
	}

	if res.Version != jsonrpcVersion {
		return nil, fmt.Errorf("received invalid jsonrpc version msg: %s", res.Version)
	}

	if res.Identifier == nil || *res.Identifier != id {
		return nil, fmt.Errorf("received message with different id")
	}

	return res.Result, nil
}

func (s *socket) close() error {
	return s.conn.Close()
}

type request struct {
	Version    string          `json:"version"`
	Method     string          `json:"method"`
	Params     json.RawMessage `json:"params"`
	Identifier uint64          `json:"id,omitempty"`
}

type response struct {
	Version    string          `json:"jsonrpc"`
	Result     json.RawMessage `json:"result"`
	Error      *responseError  `json:"error"`
	Identifier *uint64         `json:"id,omitempty"`
}

type responseError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (err *responseError) Error() string {
	return fmt.Sprintf("%d: %s %+v", err.Code, err.Message, err.Data)
}

func generateId() (id uint64) {
	for id == 0 {
		bid := make([]byte, 8)
		rand.Read(bid)
		id = binary.LittleEndian.Uint64(bid)
	}
	return
}
