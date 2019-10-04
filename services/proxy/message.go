package main

import (
	"encoding/binary"
	"time"

	"io"
	"net"

	msgpack "github.com/vmihailenco/msgpack"
)

func SendError(conn net.Conn, err error) error {
	return SendMessage(conn, ConnectionAcceptHeader{
		Error: err.Error(),
	})
}

func SendKeepAlive(conn net.Conn, tick time.Time) error {
	return SendMessage(conn, KeepAlive{
		Tick: tick.Unix(),
		Last: false,
	})
}

func SendMessage(conn net.Conn, msg interface{}) error {
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return err
	}

	var datalen int32 = int32(len(data))

	err = binary.Write(conn, binary.BigEndian, datalen)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

func RecvMessage(conn net.Conn, msg interface{}) error {
	var datalen uint32

	err := binary.Read(conn, binary.BigEndian, &datalen)
	if err != nil {
		return err
	}

	data := make([]byte, datalen)

	_, err = io.ReadFull(conn, data)
	if err != nil {
		return err
	}

	return msgpack.Unmarshal(data, msg)
}
