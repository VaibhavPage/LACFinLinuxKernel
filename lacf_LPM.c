/********************************************************************************************************************
*
* File : Cuckoo.c 
* Author - Vaibhav & Ram
*
*********************************************************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/md5.h>
#include<openssl/sha.h>
#include "LinkedList.h"

// Size of filter rows
#define FILTER_SIZE 3200

// Size of filter columns
#define FILTER_COLUMN 4 

// Number of max kicks for cuckoo filter
#define MAXNUMKICKS  500

#define FILESIZE 7000
#define PREFIX_MATCH_COUNT 30  // Used for LPM

static node* filter[FILTER_SIZE];

int addItem(char, int, int, int);   // For inserting the new items in filter
int lookupItemCuckoo(char *);  // For item lookup
int removeItem(char *, int(*lookup)(char *));  // Deletion of item if exists(call to lookup is made to check membership)
int getLength(char *);  // Length of line
int getPosition1(char *, int); // Get position i1 for item 
int getPosition2(int, char, int); // Get position i2 for item 
char fingerprint_function(char *);  // Contains logic for fingerprint creation
char generateFingerprint(char *); // Generates fingerprint
void readFromFile(char*, int);
void printAtPos(int, int, int, int);

int totalLookup = 0;
int tableCounter = 0;
int SuccessfulCounter = 0;
int lookupAccess = 0;

int insertLL(node **head, char fingerprint){
    
    int i = 0;

    node *temp;
    node *prev;

    if( *head != NULL) {
        temp = *head;
    }

    if( *head == NULL) {
            *head = (node *)malloc(sizeof(node));
            (*head)->fingerprint = fingerprint;
            (*head)->next = NULL;
            return 0;
    }

    while(i < FILTER_COLUMN){
        
        if(temp == NULL){
            temp = (node *)malloc(sizeof(node));
            (temp)->fingerprint = fingerprint;
            (temp)->next = NULL;
            prev->next = temp;
            return 0;
        } else {
            prev = temp;
            temp = temp->next;            
        }
        i++;

    }


    printf("\n Insertion exceeded 4");

    
    return -1;
        
}


int removeLL(node **head, char fingerprint){
    
    if(*head == NULL){
        return -1;
    } 
    
    if((*head)->fingerprint == fingerprint){
        
        node *temp = *head;
        *head = (*head)->next;
        free(temp);        
        return 0;

    }
    
    node *temp1 = *head;
    node *temp2;
    
    while(temp1->next != NULL){
        if(temp1->next->fingerprint == fingerprint){
            temp2 = temp1->next;
            temp1->next = temp1->next->next;
            free(temp2);            
            return 0;
        }
        temp1 = temp1->next;
    }
    
    return -1;
    
}


int searchLL(node *head, char fingerprint){
    if(head == NULL){
        return -1;
    } 
    
    while(head != NULL){
        if(head->fingerprint == fingerprint){            
            return 0;
        }
        head = head->next;
    }
    
    return -1;
    
}

/**
* Convert Hex String to Integer
* 
* @param  char *   Hex String to convert 
* return  int      Converted Integer
*/
int convertHexStringToInteger(char *hexString){
    
    unsigned int fp = 0;   // Final fingerprint 
    
   // printf("HEX STRING %s \n", hexString);
    
    while(*hexString){  // Increment till '\0'
        
        // Converting Hex to Integer
        // Simply maps characters between 0 - 16 
        if(*hexString >= 48 && *hexString <= 57 ){
            //printf("%d\n", (int)*outPtr);
            fp  += (*hexString) - 48;
        } else if(*hexString >= 97 && *hexString <= 122){
            //printf("%d\n", *outPtr);
            fp += (*hexString) - 87;   //  87 (not 97)  because A maps to 10 in hexadecimal and so on
        }
        
        ++hexString;
                
    }
    
    return fp;
    
}


/**
* Generates the 8bit fingerprint for given item.
*
* @param  char *    item 
* return  char      fingerprint
*/
char fingerprint(char *item){
    
    char *outPtr = (item + 1); 
    
    unsigned int fp = 0;   // Final fingerprint 
        
    fp = convertHexStringToInteger(outPtr);
     
    char cfp = fp & 0xff;  // Character Fingerprint 8-bit
    
    printf("\nFINGER PRINT %d\n", cfp);
    
    return cfp;
    
}

/**
* Hashes string by using MD 5.
* For further documentation read openssl MD5
*
* @param  char *   String to hash
* return  char *   Hashed String
*/
char *md5(const char *str, int length) {
    int n;
    
    MD5_CTX ctx;  // MD5 Context 
     
    unsigned char digest[16];  // Digest 
            
   // char *l = (char *) malloc(strlen(digest));
        
    char *out = (char*)malloc(33);
    
    MD5_Init(&ctx);  // Init MD5 with context

    MD5_Update(&ctx, str, length);

    /*while (length > 0) {
        
        if (length > 512) {
            
            MD5_Update(&ctx, str, 512);
            
        } else {
            
            MD5_Update(&ctx, str, length);
            
        }
        
        length -= 512;
        str += 512;
        
    }*/

    MD5_Final(digest, &ctx);  // Generate digest

    // Convert to hex string
    for (n = 0; n < 16; ++n) {
         snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }  

    char *subbuff = (char *)malloc(16);
    memcpy( subbuff, &out[0], 15 );
    subbuff[15] = '\0';
    
    //printf("\nhash value %s" , subbuff);
    
    free(out);
    
    return subbuff;
}


char *sha(char *item){
    
    int i;
    
    char *out = (char*)malloc(33);
    
    SHA512_CTX ctx;
    
    char hash[SHA_DIGEST_LENGTH];
    
    SHA512_Init(&ctx);
    
    SHA512_Update(&ctx, item, strlen(item));
    
    SHA512_Final(hash, &ctx);
    
    for (i = 0; i < 16; ++i) {
          snprintf(&(out[i*2]), 16*2, "%02x", (unsigned int)hash[i]);
    }
    
   char *subbuff = (char *)malloc(16);
    memcpy( subbuff, &out[0], 15 );
    subbuff[15] = '\0';
    
    //printf("\nhash value %s" , subbuff);
    
    free(out);
    
    return subbuff;
    
}


/**
* Generate fingerprint
*
* @param  char *   Item  
* return  char     Fingerprint
*/
char generateFingerprint(char *item){
    
    // Generates MD5 hash
    char* outMD5 = md5(item, strlen(item));
    
    // Generates fingerprint
    //char outFingerprint = fingerprint(outMD5);
  printf("\n Hash value of finger print : %s", outMD5);
  long long int i = (long long int)strtol(outMD5, NULL, 16);      // Position i1
  
    i = i >> 3;
    char cfp = (i ^ (i>>10) ^ (i>>20)) & 0xFF;
    free(outMD5);
    
    printf("\n Finger print : %d", cfp);
    
    return cfp;
    
  /*  free(outMD5);
    
    return outFingerprint;*/
    
}


/**
* Gets the position i1
*
* @param  char *   Hex String to convert
* @param  int      Mode 1 for MD5 , Mode 2 for SHA
* return  int      Converted Integer
*/
int getPosition1(char *item, int mode){
    
    char *hashOutput;
   
      if(mode == 1) {
        hashOutput = md5(item, strlen(item));
        //hashOutput = md5(hashOutput, strlen(hashOutput));
    }
    else
    {
        hashOutput = sha(item);
    }
    
    int fp = 0;
    printf("\n Hash value for position 1 : %s", hashOutput);      
    long long int i1 = (long long int)strtol(hashOutput, NULL, 16) ;      // Position i1
    
    i1 = i1 >> 3;
    //i1 = i1 ^ (i1>>8) ^ (i1>>16);
    //i1 = (i1 ^ (i1 >> 10) ^ (i1 >> 20) ^ (i1 >> 50) ^ (i1 >> 10));

    i1 = i1 % FILTER_SIZE;

    free(hashOutput);
    
    return i1; 
    
}


/**
* Gets the position i2
*
* @param  int      Position i1
* @param  char     Fingerprint 
* return  int      Position i2
* @param  int      Mode 1 for MD5 , Mode 2 for SHA
*/
int getPosition2(int i1, char fingerprint, int mode){
    
    char dummyArr[2];
    dummyArr[0] = fingerprint;
    dummyArr[1] = '\0';
    
    // Generate hex hash
     char *hashOutput = (mode == 1) ? md5(dummyArr, strlen(dummyArr)) : sha(dummyArr);
   /*  
    int i = (long long int)strtol(hashOutput, NULL, 16) % FILTER_SIZE;*/
       
   //  printf("NOT OK\n");

    long long int i = (long long int)strtol(hashOutput, NULL, 16);      // Position i1
    
    //printf("OKK\n");

    i = i >> 3;
    i = i ^ (i>>10) ^ (i>>20);
    //i = (i ^ (i >> 10) ^ (i >> 20) ^ (i >> 50) ^ (i >> 10));

    //printf("OKK 1\n");

    i = i % FILTER_SIZE;

    //printf("OKK 2\n");

    int i2 = i1 ^ i;
    
    //printf("OKK 3\n");

    if(i2 >= FILTER_SIZE){
        i2 = i2 % FILTER_SIZE;
    }
        
    
    //printf("OKK 4\n");    

    free(hashOutput);
    
    return i2;
    
}


/**
* Starting point of program
* 
*/
void startPointCuckoo(char *item){
        
    char fingerprint = generateFingerprint(item);
    
    int i1 = getPosition1(item, 1);
    
    int i2 = getPosition2(i1, fingerprint, 1);
        
    printf("I1 %d\n", i1);
    printf("I2 %d\n", i2);
    
    int pos = addItem(fingerprint, i1, i2, 1);
    
    printf("Item Added %s at position %d \n", item, pos);   
        
    pos = lookupItemCuckoo(item);
    
    printf("Item Found at position %d \n", pos);
    
}




/**
* Add fingerprint to filter
*
* @param  char     fingerprint 
* @param  int      Position i1
* @param  int      Position i2
* @param  int      Position i1
* @param  int      Position i2
* return  int      Position     -1 = Error
*
* For implementation details view research paper on LA cuckoo filter.
*/
int addItemLACF(char fingerprint ,int i1, int i2, int i11, int i12){
    
    int addI = addItem(fingerprint, i1, i2, 1);
    
    ++tableCounter;
    
    if(addI == -1)         
        return -1;    
    
    
    if(i11 != -1 && i12 != -1){        
        ++tableCounter;
        return addItem(fingerprint,i11,i12, 2) == -1 ? -1 : 0;
        
    }
        //printf("\n Add item index 2 %d", addItem(fingerprint,i11,i12));
        
       
    return 0;
            
}


/**
* Add fingerprint to filter
*
* @param  char     fingerprint 
* @param  int      Position i1
* @param  int      Position i2
* return  int      Position     -1 = Error
*
* For implementation details view research paper on cuckoo filter.
*/
int addItem(char fingerprint, int i1, int i2, int mode){
    
    int n = 0;

    int i;

    
    if(insertLL(&filter[i1], fingerprint) == 0){
        printf("\nInserted at Position i1 / i11 : %d", i1);
        
      return i1;
    }
    
   
    if(insertLL(&filter[i2], fingerprint) == 0 ){
         printf("\nInserted at Position i2 / i12 : %d", i2);
         
        return i2;
    }

    int bucketPos;
    
    //bucketPos = (bucketPos == 0) ? i1 : i2;

    bucketPos = i1;
    
    char dummyArr[2];
            
    dummyArr[1] = '\0';
    
    char *hashOutput;
    
    for(n = 0; n < MAXNUMKICKS; n++){
                    
        
        char temp = (filter[bucketPos])->fingerprint;
        (filter[bucketPos])->fingerprint = fingerprint;
        fingerprint = temp;
        
        // Better call getposition 2 here
        
       /* dummyArr[0] = fingerprint;
        if(mode == 1) {
        hashOutput = md5(dummyArr, strlen(dummyArr));
        } else {
            hashOutput = sha(dummyArr);
        }*/
                
        //i = (long long int)strtol(hashOutput, NULL, 16) % FILTER_SIZE;
        
       // bucketPos = bucketPos ^  i;

       // printf("Seg Fault going to happen\n");

        bucketPos = getPosition2(bucketPos, fingerprint, mode);
       /* 
        if(bucketPos >= FILTER_SIZE){
            bucketPos = bucketPos % FILTER_SIZE;
        }
        */
       // free(hashOutput);
                
        if(insertLL(&filter[bucketPos], fingerprint) == 0){
            printf("\n fingerprint %d is kicked to %d",fingerprint, bucketPos);
            return bucketPos;
        }
        
        
    }
    
    printf("\nMax kicks %d ",n);
    
    return -1;
    
}


/**
* Searches fingerprint in filter
*
* Returns bucket index or -1 if not found
*/
int lookupItemCuckoo(char *item){   
    
    ++lookupAccess;

    int i1 = getPosition1(item, 1);
    char fingerprint = generateFingerprint(item);
    
    int i2 = getPosition2(i1, fingerprint, 1);
    
    printf("\n Lookup I1 %d and I2 %d", i1, i2);
    
    int i;
       
    if(searchLL(filter[i1], fingerprint) == 0) {       
       return i1;
    }

    if(searchLL(filter[i2], fingerprint) == 0){       
       return i2; 
    }
     
    return -1;
    
}

int lookupItemLACF(char *item){
    
    int popularity = findPopularity(strlen(item));
    
    printf("\nPop : %d", popularity);    
        
    if(popularity == 1){       
        return (lookupItemCuckoo(item) == -1 ? -1 : 0);     
    } else {
       // printf("Ok\n");
        return (lookupItemCuckoo(item) == -1 || lookupItemLACFNonPopular(item) == -1 ? -1 : 0);
           
    }    
        
}


/**
* Searches fingerprint in filter
*
* Returns bucket index or -1 if not found
*/
int lookupItemLACFNonPopular(char *item){
    
   // printf("Inside NONPOP \n");

    ++lookupAccess;

    int itemLength = strlen(item);
    
    char fingerprint = generateFingerprint(item);
       
    //printf("Working till here \n");   
       
    int i11 = getPosition1(item, 2);
    //printf("Working till here 1\n");
    int i12 = getPosition2(i11, fingerprint, 2);
    
    //printf("Working till here 2\n");
    
    printf("\n Lookup I11 %d and I12 %d", i11, i12);
    
    if( searchLL(filter[i11], fingerprint) > -1){
        return i11;
    }
    
    if(searchLL(filter[i12], fingerprint) > -1 ){
        return i12;  
    }    
    return -1;
} 

/**
* Removes fingerprints from filter
*
*/
int removeItem(char *item, int (*lookup)(char *)){
    
    int bucketIndex = lookup(item);
    
    printf("\nbucket index %d ", bucketIndex);
    
    char fingerprnt = generateFingerprint(item);
    
    if(bucketIndex != -1){
        int i = 0;
       
        if(removeLL(&filter[bucketIndex], fingerprnt) == 0) {
            return 0;
        } else {
            return -1;
        }
            
    } else {
        printf("\n Can not delete the item as it is not present in the filter");
        return -1;
    }    
}


/**
* Remove fingerprint from LACF
*
*/
int removeItemLACF(char *item){
    
    int popularity = findPopularity(strlen(item));
    
    if(removeItem(item, lookupItemCuckoo) == -1) return -1;
    
    if(popularity == 2){
        
        return removeItem(item, lookupItemLACFNonPopular) == -1 ? -1 : 0;
                                
    }
    
    return 0;
    
}


void display(void){

    int i = 0;
    node *temp;

    while(i < FILTER_SIZE){
        temp = filter[i];
      //  printf("Temp %p", temp);
        while(temp != NULL){
            printf("Fingerprint %d Position %d \n", temp->fingerprint, i);
            temp = temp->next;
        }
        i++;
    }

}



/**
* Starting point for LACF
*
* @param   item
*/
void startPointLACF(){
        
    int choice = 0;
     int i1 , i2, i11, i12;
    char* filename = (char *)malloc(100);
    
    while(1){
        
        printf("1. Insert Item/s \n");
        printf("2. Lookup Item/s \n");
        printf("3. Delete Item/s \n");
        printf("4. Display first 10 entries\n");
        printf("5. Table Counter \n");
		printf("6. Performance False Positive \n");
        printf("7. Lookup Access \n");
        printf("8. Exit/s \n");
        printf("Enter your choice : ");
        scanf("%d", &choice);
        printf("\n");
        
        if(choice == 8 || choice > 8 || choice < 1) break;
        
        switch(choice){
            case 1:
               printf("Enter file name : ");
               scanf("%s", filename);
               printf("%s", filename);
               readFromFile(filename, choice);
               break;
           case 2:
               printf("Enter file name : ");
               scanf("%s", filename);
               readFromFile(filename, choice);
               break;
           case 3:
               printf("Enter file name : ");
               scanf("%s", filename);
               readFromFile(filename, choice);
               break;
            case 4:
              
                printf("Enter four values\n ");
                
                scanf("%d", &i1);
                scanf("%d", &i2);
                scanf("%d", &i11);
                scanf("%d", &i12);
                
                printAtPos(i1, i2, i11, i12);
                
                break;
                
            case 5:
                printf("tableCounter is %d \n", tableCounter);
                printf("table Occupancy is %f \n", (double)(tableCounter * 100) / (FILTER_SIZE * FILTER_COLUMN) );
                break;
				
			case 6 :
                printf("SuccessfulCounter = %d   totalLookup = %d", SuccessfulCounter, totalLookup);
				printf("False Positive rate in percentage is %f \n", (double)(SuccessfulCounter) / totalLookup );
                break;

            case 7:
                printf("Lookup Accesses are %d\n", lookupAccess);
                break;
        }
        
    }
            
}


/**
* print fingerprint at given position 
*/
void printAtPos(int i1, int i2, int i11, int i12){
    
    node *temp = filter[i1];
    
    printf("Fingerprint at %d\n", i1);
    
    while(temp != NULL){
        printf("%d " , temp->fingerprint);
        temp = temp->next;
    }
    
    temp = filter[i2];
    
    printf("Fingerprint at %d\n", i2);
    
    while(temp != NULL){
        printf("%d " , temp->fingerprint);
        temp = temp->next;
    }
    
    if(i11 != -1){
        
        temp = filter[i11];
        
        printf("Fingerprint at %d\n", i11);
        
        while(temp != NULL){
            printf("%d " , temp->fingerprint);
            temp = temp->next;
        }
            
    }
    
    if(i12 != -1){
        temp = filter[i12];
    
        printf("Fingerprint at %d\n", i12);
        
        while(temp != NULL){
            printf("%d " , temp->fingerprint);
            temp = temp->next;
        }
        
    }
    
    printf("\n");
    
}


/**
* LACF prefix popularity(Just Temporary)
* 
* @param   itemLength   length of item
* return   popularity   -1 Not possible, 1 very popular, 2 less popular 
*
*/
int findPopularity(int itemLength){
    
    //itemLength = itemLength;  // To remove '\0'
    printf("Item length : %d", itemLength);
    if(itemLength == 0) return -1;
        
    if(itemLength >= 14 && itemLength <= 24){        
         return 1;
    }
    
    return 2;
    
}

/**
* Read from input file
*
*/
void readFromFile(char *fileName, int choice){
    
    FILE *fp = fopen(fileName,"r");
    
    int number_of_prefix_match;  // Runs search 24 times from 32 prefix till prefix length of 8

    printf("Hello\n");
    
    int size = 40;
    char* item = (char *) malloc(size);
    char fingerprint;
    int i1, i2, i11, i12;
    int itemLength;
    int retAdd;
        
    while(1) {
    
        fgets(item, size, fp); 
          
                 
        item[strcspn(item,"\n")] = 0;    
        int len = strlen(item);
        printf("\nLength of String : %d", len);      
        // Generate the fingerprint
        fingerprint = generateFingerprint(item);
        
        number_of_prefix_match = PREFIX_MATCH_COUNT;

        // Get position i1
        i1 = getPosition1(item, 1);
        
        i11 = -1;
        i12 = -1;
        
        // Get position i2
        i2 = getPosition2(i1, fingerprint, 1);
        
        itemLength = strlen(item);
        
        if(findPopularity(itemLength) == 2) {
            
            i11 = getPosition1(item, 2);
            i12 = getPosition2(i11, fingerprint, 2);
                    
        } else {
            printf("\nItem IP %s", item);
        }
        
        
       /* printf("Position i1 %d\n", i1);
        printf("Position i2 %d\n", i2);
        printf("Position i11 %d\n", i11);
        printf("Position i12 %d\n", i12); */
        
        
        if(choice == 1){
            printf("\n i1 %d i2 %d i11 %d i12 %d", i1,i2,i11,i12);
            

            retAdd = addItemLACF(fingerprint, i1, i2, i11, i12);
        
            printf("\n Add item Ret Val % d", retAdd);
        } else if(choice == 2){

            int flag = 0;
            if(strlen(item) < 32) {
                flag = -1;
            }
            // Longest Prefix Match
            while(number_of_prefix_match >= 0 && flag == 0){

                printf("\n Looking up %s" , item);
                
                if(lookupItemLACF(item) == -1) {
                    printf("\n Unsuccessful %s", item);
                    --number_of_prefix_match;
                    --itemLength;
                    item[itemLength] = '\0';
                    ++totalLookup;
                    printf("lookupAccess %d \n" , lookupAccess);                   
                }
                else {
                    printf("\n Successful %s number_of_prefix_match %d ", item, (number_of_prefix_match + 2));
                    ++SuccessfulCounter;
                    break;
                }

            }

        } else {
            
            printf("\n Removing %s ", item);
            removeItemLACF(item);
            printf("\n Removed ");
            
        }
        
        if(feof(fp)){            
            break;
        }
    
    }            
        
}


/*
* Main function
*/
int main(int argc, char *argv[]) {
      
    ++argv;
    
   // initializeFilter();
    
    char *fileName = *argv;
    
    //readFromFile(fileName);
    
    startPointLACF();
        
    // printf("%s\n", output);
    // free(output);
    return 0;
}