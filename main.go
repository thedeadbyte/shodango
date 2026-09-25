package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/joho/godotenv"
)

type ShodanResponse struct {
	IP        string
	Ports     []int
	Vulns     []string
	RawOutput string
	Err       error
}

// Pull project envs
func getProjectEnv() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("There was an issue loading the environmental variable: ", err)
	}
	return os.Getenv("SHODAN_API_KEY")
}

func worker(jobs <-chan string, results chan<- ShodanResponse, wg *sync.WaitGroup, key string) {
	defer wg.Done()
	v := url.Values{}
	v.Set("key", key)
	vEncoded := v.Encode()
	base := "https://api.shodan.io/shodan/host"

	for j := range jobs {
		shodanURLBase, err := url.JoinPath(base, j)
		if err != nil {
			log.Print(err)
			continue
		}
		shodanURLFull := shodanURLBase + "?" + vEncoded
		//fmt.Println(shodanURLFull)
		callApi, err := http.Get(shodanURLFull)
		if err != nil {
			log.Println(err)
			continue
		}
		if callApi.StatusCode != 200 {
			fmt.Println(callApi.StatusCode)
			callApi.Body.Close()
			continue
		}
		sBody, err := io.ReadAll(callApi.Body)
		callApi.Body.Close()
		if err != nil {
			log.Println(err)
			continue
		}
		results <- ShodanResponse{IP: j, RawOutput: string(sBody)}
	}
}

func main() {
	// handle flags
	ipPath := flag.String("ipFile", "", "Path the the files containing ips")
	//	outFile := flag.String("outputFile", "", "Outputs a json file with the name you choose here. (optional)")
	wCount := flag.Int("workerCount", 2, "Default workers set to 5, please (carefully) add and int for the amount of workers you want")
	flag.Parse()

	// load the env var
	shodanAPIKey := getProjectEnv()

	// init the channels
	jobs := make(chan string)
	results := make(chan ShodanResponse)
	var wg sync.WaitGroup

	// start the workers
	maxWorker := 2
	if *wCount > maxWorker {
		log.Fatalf("You have exeed the max amount of workers allowed: %v", maxWorker)
	}
	for i := 0; i < *wCount; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, shodanAPIKey)

	}

	// open up the file
	go func() {
		ipFile, err := os.Open(*ipPath)
		if err != nil {
			log.Fatal(err)
		}
		defer ipFile.Close()
		scanner := bufio.NewScanner(ipFile)
		for scanner.Scan() {
			jobs <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Non fatal error occurred: %v", err)
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collection, ranges over output, prints to stdout and json if specified
	for r := range results {
		fmt.Println(r.RawOutput)
	}
}
