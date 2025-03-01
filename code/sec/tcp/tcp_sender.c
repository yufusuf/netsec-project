#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP getenv("INSECURENET_HOST_IP")
#define SERVER_PORT 8888
#define MESSAGE "hello insec"
#define INTERVAL 1

int main() {
   int sockfd;
   struct sockaddr_in server_addr;
   char *message = MESSAGE;

   // Print server IP and port
   printf("Server IP: %s\n", SERVER_IP);
   printf("Server Port: %d\n", SERVER_PORT);
   // Create socket
   if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("Socket creation failed");
      exit(EXIT_FAILURE);
   }

   // Set server address
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(SERVER_PORT);
   if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
      perror("Invalid address/ Address not supported");
      close(sockfd);
      exit(EXIT_FAILURE);
   }

   // Connect to server
   if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      perror("Connection failed");
      close(sockfd);
      exit(EXIT_FAILURE);
   }
   // Print connection success message
   printf("Connected to server %s on port %d\n", SERVER_IP, SERVER_PORT);
   while (1) {
      // Send message
      if (send(sockfd, message, strlen(message), 0) < 0) {
         perror("Send failed");
         close(sockfd);
         exit(EXIT_FAILURE);
      }
      printf("Message sent: %s\n", message);

      // Wait for the interval
      sleep(INTERVAL);
   }

   // Close socket
   close(sockfd);
   return 0;
}