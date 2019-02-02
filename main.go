package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gocolly/colly"
)

func main() {
	collector := colly.NewCollector()
	collector.OnHTML("a[href]", func(element *colly.HTMLElement) {
		element.Request.Visit(element.Attr("href"))
	})
	collector.OnRequest(func(request *colly.Request) {
		fmt.Println("Visiting", request.URL)
	})

	http.HandleFunc("/crawl", func(writer http.ResponseWriter, request *http.Request) {
		request.ParseForm()
		urls, ok := request.Form["url"]
		if !ok || len(urls) < 1 {
			log.Println("request error: no URL provided!")
			return
		}

		for _, url := range urls {
			log.Println("request arrived from", request.Host, "to crawl over the links in", url)
			collector.Visit(url)
		}
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
