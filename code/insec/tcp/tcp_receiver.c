#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8888
#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 4

typedef struct {
  int socket;
  struct sockaddr_in address;
} client_t;

void *handle_client(void *arg) {
  client_t *client = (client_t *)arg;
  char buffer[BUFFER_SIZE] = {0};
  const char *hello = "Hello from insecure server";

  while (1) {
    int valread = read(client->socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
      break;
    }
    printf("Received: %s\n", buffer);
    send(client->socket, hello, strlen(hello), 0);
    printf("Hello message sent\n");
    memset(buffer, 0, BUFFER_SIZE); // Clear the buffer
  }

  close(client->socket);
  free(client);
  return NULL;
}

int main() {
  int server_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  pthread_t thread_pool[THREAD_POOL_SIZE];

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8888
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    perror("setsockopt");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  const char *host_ip = getenv("INSECURENET_HOST_IP");
  if (host_ip == NULL) {
    perror("Environment variable INSECURENET_HOST_IP not set");
    close(server_fd);
    exit(EXIT_FAILURE);
  }
  address.sin_addr.s_addr = inet_addr(host_ip);
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8888
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0) {
    perror("listen");
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  while (1) {
    client_t *client = (client_t *)malloc(sizeof(client_t));
    if (!client) {
      perror("malloc failed");
      continue;
    }

    client->socket = accept(server_fd, (struct sockaddr *)&client->address, (socklen_t*)&addrlen);
    if (client->socket < 0) {
      perror("accept");
      free(client);
      continue;
    }

    // Print the IP address and source port of the connecting client
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client->address.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client->address.sin_port);
    printf("Connection from %s:%d\n", client_ip, client_port);
    // Find an available thread in the pool
    int i;
    for (i = 0; i < THREAD_POOL_SIZE; i++) {
      if (pthread_join(thread_pool[i], NULL) == 0) {
        pthread_create(&thread_pool[i], NULL, handle_client, (void *)client);
        break;
      }
    }

    // If no threads are available, wait for one to finish
    if (i == THREAD_POOL_SIZE) {
      pthread_join(thread_pool[0], NULL);
      pthread_create(&thread_pool[0], NULL, handle_client, (void *)client);
    }
  }

  close(server_fd);
  return 0;
}