/**
 * Cisco Systems NetFlow Services Export Version 9 parser.
 * referenced from : https://www.rfc-editor.org/rfc/rfc3954#section-11.3
*/
#include <stdio.h>
#include <stdlib.h>

/**
 * using udp protocol to fetch these data.
 * when you receive these data, you need to use unsigned char[], not char[].
*/
const unsigned char* template = "0009000196"
								"6EFEBF6603"
								"1732000030"
								"70001F8100"
								"0000006C05"
								"2300190008"
								"0004000C00"
								"04000F0004"
								"0002000400"
								"0100040016"
								"0004001500"
								"0400120004"
								"000A000200"
								"0E00020007"
								"0002000B00"
								"0200100002"
								"0011000200"
								"3A0002003B"
								"000200E800"
								"0200060001"
								"0004000100"
								"0500010009"
								"0001000D00"
								"01003D0001"
								"0059000100"
								"D20003";

const unsigned char* dataset = "000900019b3da36066045"
								"30100003214001f810005"
								"2300400aa3ff310aa3ff3"
								"10aa3ff31000000010000"
								"05ea9b3bede09b3bede00"
								"000000000140014000000"
								"000000000000000000000"
								"00001e01e1e0100000000";

const char* getFieldTypeByValue(int value){
	switch(value){
		case 1: return "IN_BYTES";
		case 2: return "IN_PKTS";            
		case 3: return "FLOWS";            
		case 4: return "PROTOCOL";           
		case 5: return "TOS";                
		case 6: return "TCP_FLAGS";          
		case 7: return "L4_SRC_PORT";        
		case 8: return "IPV4_SRC_ADDR";      
		case 9: return "SRC_MASK";           
		case 10: return "INPUT_SNMP";        
		case 11: return "L4_DST_PORT";       
		case 12: return "IPV4_DST_ADDR";     
		case 13: return "DST_MASK";          
		case 14: return "OUTPUT_SNMP";       
		case 15: return "IPV4_NEXT_HOP";     
		case 16: return "SRC_AS";            
		case 17: return "DST_AS";            
		case 18: return "BGP_IPV4_NEXT_HOP"; 
		case 19: return "MUL_DST_PKTS";      
		case 20: return "MUL_DST_BYTES";     
		case 21: return "LAST_SWITCHED";     
		case 22: return "FIRST_SWITCHED";    
		case 23: return "OUT_BYTES";         
		case 24: return "OUT_PKTS";          
		case 27: return "IPV6_SRC_ADDR";     
		case 28: return "IPV6_DST_ADDR";        
		case 29: return "IPV6_SRC_MASK";        
		case 30: return "IPV6_DST_MASK";        
		case 31: return "IPV6_FLOW_LABEL";      
		case 32: return "ICMP_TYPE";            
		case 33: return "MUL_IGMP_TYPE";        
		case 34: return "SAMPLING_INTERVAL";    
		case 35: return "SAMPLING_ALGORITHM";   
		case 36: return "FLOW_ACTIVE_TIMEOUT";  
		case 37: return "FLOW_INACTIVE_TIMEOUT";
		case 38: return "ENGINE_TYPE";          
		case 39: return "ENGINE_ID";            
		case 40: return "TOTAL_BYTES_EXP";      
		case 41: return "TOTAL_PKTS_EXP";       
		case 42: return "TOTAL_FLOWS_EXP";      
		case 46: return "MPLS_TOP_LABEL_TYPE";         
		case 47: return "MPLS_TOP_LABEL_IP_ADDR";      
		case 48: return "FLOW_SAMPLER_ID";             
		case 49: return "FLOW_SAMPLER_MODE";           
		case 50: return "FLOW_SAMPLER_RANDOM_INTERVAL";
		case 55: return "DST_TOS";            
		case 56: return "SRC_MAC";            
		case 57: return "DST_MAC";            
		case 58: return "SRC_VLAN";           
		case 59: return "DST_VLAN";           
		case 60: return "IP_PROTOCOL_VERSION";
		case 61: return "DIRECTION";          
		case 62: return "IPV6_NEXT_HOP";      
		case 63: return "BGP_IPV6_NEXT_HOP";  
		case 64: return "IPV6_OPTION_HEADERS";
		case 70: return "MPLS_LABEL_1"; 
		case 71: return "MPLS_LABEL_2"; 
		case 72: return "MPLS_LABEL_3"; 
		case 73: return "MPLS_LABEL_4"; 
		case 74: return "MPLS_LABEL_5"; 
		case 75: return "MPLS_LABEL_6"; 
		case 76: return "MPLS_LABEL_7"; 
		case 77: return "MPLS_LABEL_8"; 
		case 78: return "MPLS_LABEL_9"; 
		case 79: return "MPLS_LABEL_10";
		case 210: return "paddingOctets";
		case 232: return "responderOctets";
		default: return NULL;
	}
}

typedef struct Header {
	long versionNumber;
	long count;
	long long sysUpTime;
	long long unixSecs;
	long long sequenceNumber;
	long long sourceId;
} Header;

typedef struct Field {
	int fieldType;
	int fieldLength;	
} Field;

typedef struct TemplateFlowSet {
	long flowSetId;
	long length;
	long templateId;
	long fieldCount;

	Field* fields;
	int fieldsLen;
} TemplateFlowSet;

int hexToDec(unsigned char c) {
    if (c >= '0' && c <= '9'){
        return c - '0';
	}
    else if (c >= 'A' && c <= 'F'){
        return c - 'A' + 10;
	}
    else if (c >= 'a' && c <= 'f'){
        return c - 'a' + 10;
	}
    else{
        return -1;
	}
}

long long hexStrToDec(const unsigned char* text, int len){
	int i = 0;
	long long result = 0;

	while (len > 0){
		result = 16 * result + hexToDec(text[i]);
		--len;
		++i;
	}

	return result;
}

Header* parseHeader(const unsigned char* text){
	Header* header = (Header*)malloc(sizeof(Header));
	if (header == NULL){
		return NULL;
	}

	header->versionNumber = (long)hexStrToDec(text, 4);
	text += 4;
	header->count = (long)hexStrToDec(text, 4);
	text += 4;
	header->sysUpTime = hexStrToDec(text, 8);
	text += 8;
	header->unixSecs = hexStrToDec(text, 8);
	text += 8;
	header->sequenceNumber = hexStrToDec(text, 8);
	text += 8;
	header->sourceId = hexStrToDec(text, 8);

	return header;
}

void destroyHeader(Header* header){
	free(header);
}

void printHeader(const Header* header){
	printf("Header:\n");
	printf("  versionNumber: %ld\n", header->versionNumber);
	printf("  count: %ld\n", header->count);
	printf("  sysUpTime: %lld\n", header->sysUpTime);
	printf("  unixSecs: %lld\n", header->unixSecs);
	printf("  sequenceNumber: %lld\n", header->sequenceNumber);
	printf("  sourceId: %lld\n", header->sourceId);
}

TemplateFlowSet* parseTemplateFlowSet(const unsigned char* text){
	int i;
	TemplateFlowSet* tfs = (TemplateFlowSet*)malloc(sizeof(TemplateFlowSet));
	if (tfs == NULL){
		return NULL;
	}

	tfs->flowSetId = (long)hexStrToDec(text, 4);
	text += 4;
	tfs->length = (long)hexStrToDec(text, 4);
	text += 4;
	tfs->templateId = (long)hexStrToDec(text, 4);
	text += 4;
	tfs->fieldCount= (long)hexStrToDec(text, 4);
	text += 4;

	tfs->fieldsLen = (tfs->length - 16) / 4;
	tfs->fields = (Field*)malloc(tfs->fieldsLen * sizeof(Field));
	if (tfs->fields == NULL){
		free(tfs);
		return NULL;
	}

	for (i = 0; i < tfs->fieldsLen; ++i){
		tfs->fields[i].fieldType = (int)hexStrToDec(text, 4);
		text += 4;
		tfs->fields[i].fieldLength = (int)hexStrToDec(text, 4);
		text += 4;
	}

	return tfs;
}

void destroyTemplateFlowSet(TemplateFlowSet* tfs){
	free(tfs->fields);
	free(tfs);
}

void printTemplateFlowSet(const TemplateFlowSet* tfs){
	int i;

	printf("template flowSet:\n");
	printf("  flowSetId: %ld\n", tfs->flowSetId);
	printf("  length: %ld\n\n", tfs->length);
	printf("  fields:\n");

	for (i = 0; i < tfs->fieldsLen; ++i){
		printf("    %d, %s: %ld\n", tfs->fields[i].fieldType, 
									getFieldTypeByValue(tfs->fields[i].fieldType), 
									tfs->fields[i].fieldLength);
	}
}

int main(){
	Header* header = parseHeader(template);
	TemplateFlowSet* tfs = parseTemplateFlowSet(template + 40);

	printHeader(header);
	printf("\n");
	printTemplateFlowSet(tfs);

	destroyHeader(header);
	destroyTemplateFlowSet(tfs);
	return 0;
}
