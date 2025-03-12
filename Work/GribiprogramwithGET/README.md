# gribiProgramWithGet

Script to read gRIBI Get Response messages in textproto format from a folder and craft gribi Modify requests and sent it to a target device. 

## How to Run
- Copy all files
- run `go mod tidy` to download required packages
- run `go run gribiProgramWithGet.go` to start the script
- variable `dirToParse` should be set to directory containing all request files
- all GetResponse filenames should end with pattern set in variable `responseSuffix`.