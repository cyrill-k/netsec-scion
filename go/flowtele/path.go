package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

type scionPathDescription struct {
	IAList []addr.IA
	IDList []common.IFIDType
}

func (spd *scionPathDescription) IsEmpty() bool {
	return (spd.IAList == nil && spd.IDList == nil) || len(spd.IAList) == 0 && len(spd.IDList) == 0
}

func (spd *scionPathDescription) Set(input string) error {
	if input == "" {
		spd.IAList = make([]addr.IA, 0)
		spd.IDList = make([]common.IFIDType, 0)
		return nil
	}
	isdasidList := strings.Split(input, ">")
	spd.IAList = make([]addr.IA, 2*(len(isdasidList)-1))
	spd.IDList = make([]common.IFIDType, 2*(len(isdasidList)-1))
	reFirst := regexp.MustCompile(`^([^ ]*) (\d+)$`)
	reIntermediate := regexp.MustCompile(`^(\d+) ([^ ]*) (\d+)$`)
	reLast := regexp.MustCompile(`^(\d+) ([^ ]*)$`)
	if len(isdasidList) < 2 {
		return fmt.Errorf("Cannot parse path of length %d", len(isdasidList))
	}
	index := 0
	for i, iaidString := range isdasidList {
		var elements []string
		var inId, outId, iaString string
		switch i {
		case 0:
			elements = reFirst.FindStringSubmatch(iaidString)
			iaString = elements[1]
			outId = elements[2]
		case len(isdasidList) - 1:
			elements = reLast.FindStringSubmatch(iaidString)
			inId = elements[1]
			iaString = elements[2]
		default:
			elements = reIntermediate.FindStringSubmatch(iaidString)
			inId = elements[1]
			iaString = elements[2]
			outId = elements[3]
		}
		ia, err := addr.IAFromString(iaString)
		if err != nil {
			return err
		}
		if inId != "" {
			spd.IAList[index] = ia
			err = spd.IDList[index].UnmarshalText([]byte(inId))
			index++
		}
		if outId != "" {
			spd.IAList[index] = ia
			err = spd.IDList[index].UnmarshalText([]byte(outId))
			index++
		}
	}
	return nil
}

func (spd *scionPathDescription) String() string {
	if len(spd.IAList) < 2 {
		return "<Empty SCION path description>"
	}
	var sb strings.Builder
	for i := 0; i < len(spd.IAList); i++ {
		if i%2 == 0 {
			sb.WriteString(spd.IAList[i].String())
			sb.WriteString(" ")
			sb.WriteString(spd.IDList[i].String())
		} else {
			sb.WriteString(">")
			sb.WriteString(spd.IDList[i].String())
			sb.WriteString(" ")
		}
	}
	sb.WriteString(spd.IAList[len(spd.IAList)-1].String())
	return sb.String()
}

func (spd *scionPathDescription) IsEqual(other *scionPathDescription) bool {
	if len(spd.IAList) != len(other.IAList) {
		return false
	}
	for i, isdas := range spd.IAList {
		if isdas != other.IAList[i] || spd.IDList[i] != other.IDList[i] {
			return false
		}
	}
	return true
}

func NewScionPathDescription(p snet.Path) *scionPathDescription {
	var spd scionPathDescription
	spd.IAList = make([]addr.IA, len(p.Metadata().Interfaces))
	spd.IDList = make([]common.IFIDType, len(p.Metadata().Interfaces))
	for i, ifs := range p.Metadata().Interfaces {
		spd.IAList[i] = ifs.IA
		spd.IDList[i] = ifs.ID
	}
	return &spd
}

func readPaths(pathsFile string) ([]*scionPathDescription, error) {
	f, err := os.Open(pathsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	spds := make([]*scionPathDescription, 0)
	for scanner.Scan() {
		var spd scionPathDescription
		spd.Set(scanner.Text())
		spds = append(spds, &spd)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return spds, nil
}
