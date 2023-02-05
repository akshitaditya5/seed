#include<bits/stdc++.h>
#include <time.h>
using namespace std;
class Transaction 
{
    public:
            string Customer,SellersName,Seed;          // keeping the following as the seed of a Transaction
            time_t Time;
            Transaction(string Customer, string SellersName,string Seed,time_t Time)
            {
                this->Customer=Customer;
                this->SellersName=SellersName;
                this->Time=Time;
            }
};
// SHA256 library taken from online source to use SHA256 hashing algorithm 
#define uchar unsigned char
#define uint unsigned int

#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
	uchar data[64];
	uint datalen;
	uint bitlen[2];
	uint state[8];
} SHA256_CTX;

uint k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX *ctx, uchar data[])
{
	uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX *ctx, uchar data[], uint len)
{
	for (uint i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			SHA256Transform(ctx, ctx->data);
			DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
			ctx->datalen = 0;
		}
	}
}

void SHA256Final(SHA256_CTX *ctx, uchar hash[])
{
	uint i = ctx->datalen;

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;

		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;

		while (i < 64)
			ctx->data[i++] = 0x00;

		SHA256Transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	SHA256Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

string SHA256(char* data) {
	int strLen = strlen(data);
	SHA256_CTX ctx;
	unsigned char hash[32];
	string hashStr = "";

	SHA256Init(&ctx);
	SHA256Update(&ctx, (unsigned char*)data, strLen);
	SHA256Final(&ctx, hash);

	char s[3];
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);
		hashStr += s;
	}

	return hashStr;
}
  // SHA 256 library ends
string hashTxn(string h)
{
    char c[h.size()];
    for(int i=0;i<h.size();i++)
    {
        c[i]=h[i];
    }
    return SHA256(c);
}
string hashTxn(Transaction *t1)
{
    string s=t1->Customer+t1->SellersName+t1->Seed;   // calculating hash of the block
    char c[s.length()];
    for(int i=0;i<s.size();i++)
    {
        c[i]=s.at(i);     // converting to character array as the SHA library requires to do so 
    }
    return SHA256(c);    // Using the predefined function 
}


class Merkle
{
    public:
            //node*root;
            string hash;
           string getHash(Transaction* t1,Transaction* t2, Transaction* t3, Transaction* t4 )
           {
              makeMerkle(t1,t2,t3,t4);
              return this->hash;
           }
            void makeMerkle(Transaction* t1,Transaction* t2, Transaction* t3, Transaction* t4 )
            {
                string h1,h2,h3,h4;
                h1= hashTxn(t1);
                h2= hashTxn(t2);
                h3= hashTxn(t3);
                h4= hashTxn(t4);
                vector<string>m;
                m.push_back(h1);
                m.push_back(h2);
                m.push_back(h3);
                m.push_back(h4);
                h1=hashTxn(h1+h2);
                m.push_back(h1);
                h2=hashTxn(h3+h4);
                this->hash=hashTxn(h1+h2);
                //initiateMerkle(root,6);
                //fillMerkle(h1,h2,h3,h4);
            }
       
};

class Block
{
    public:
            string prevHash;
            int index;
            string Hashed;
            Transaction* t1;Transaction* t2;Transaction* t3;Transaction* t4;
            Block(string prevHash,int index,Transaction* t1,Transaction* t2,Transaction* t3,Transaction* t4)
            {
                this->prevHash=prevHash;
                this->index=index;
                this->t1=t1;
                this->t2=t2;
                this->t3=t3;
                this->t4=t4;
                makeMerkle(t1,t2,t3,t4);             // calculating merkle root hash
            }
            void makeMerkle(Transaction* t1,Transaction* t2, Transaction* t3, Transaction* t4 )
            {
                string h1,h2,h3,h4;
                h1= hashTxn(t1);
                h2= hashTxn(t2);
                h3= hashTxn(t3);
                h4= hashTxn(t4);
                vector<string>m;
                m.push_back(h1);
                m.push_back(h2);
                m.push_back(h3);
                m.push_back(h4);
                h1=hashTxn(h1+h2);
                m.push_back(h1);
                h2=hashTxn(h3+h4);
                this->Hashed=hashTxn(h1+h2);
            }
            
};

// POET Application
Block* mineBlock(string prevHash,int n,Transaction* t1,Transaction*t2,Transaction*t3,Transaction*t4)
{
    time_t current;
    current=time(nullptr);
    srand(time(0));
    int t = 1+rand()%10;              // keeping the range of time to elapse in the range of 1-9 secs
    while(time(nullptr)!= current+t)   // delaying the node till the that time has been covered 
    {}
    Block* b= new Block(prevHash,n,t1,t2,t3,t4);
    return b;
}

// POET Ends
vector<Transaction> txn;
vector<Block> blockchain;
vector<pair<string,string>>user;
map<string,string>hisOwner;     // using hash map to store history of the seed that owners have
map<string,string>hisProp;      // using hash map to store the history of ownership of seed
string history="";
void transaction()
{
	cout<<"Enter customer's name, seller's name and seeds being sold respectively"<<endl;
	string customer ,seller,seed;
	cin>>customer>>seller>>seed;
	string f=hisOwner[seller];
    int i=0;
    if(f.find(seed)==f.npos)    // checking if the seed is been owned by the seller or not
	{
		cout<<"Couldnt process the Transaction"<<endl;
        return;
	}
	time_t current=time(nullptr);               // saving the current time for the timestamp
	Transaction *t=new Transaction(customer,seller,seed,current);
	txn.push_back(*t);       // making a Transaction pool where all the Transactions are saved 
	hisOwner[customer]+=(" "+seed);    // updating the records accordingly
	int start=f.find(seed),end=start+seed.size()-1;
	string p1=f.substr(0,start);
	string p2=f.substr(end+1,f.size()-end -1);
	hisOwner[seller]=p1+p2;
	hisProp[seed]+=(" -> " + customer);
	if(txn.size()==4)        
	{
        string prevHash="";
        if(blockchain.size()!=0)
		 prevHash=blockchain.at(blockchain.size()-1).Hashed;
		srand(time(nullptr));
		int node=rand()%(user.size());         // calculating the node which will be used for the consencous Algorithm
		Block * a=mineBlock(prevHash,node,&txn[0],&txn[1],&txn[2],&txn[3]);  // using single block to save 4 Transactions
        blockchain.push_back(*a);
        for(int j=0;j<4;j++)
        {
            txn.pop_back();
        }
	
	user[i].second="";
	for( i=0;i<user.size();i++)
	{
		if(user[i].first==customer)
		{
			user[i].second+=seed;
			break;
		}
	}
	history+=(user[i].first +" owns " + user[i].second+" ");
    }
}
void History()
{
	string seed;
  cout<<"Enter the seed name for which u want history"<<endl;
  cin>>seed;
  cout<<hisProp[seed]<<endl;
}
int main()                   // main function of the program
{
	cout<<"----------------SESSION START------------------"<<endl;
	cout<<"register all  the users first"<<endl;
	cout<<" Enter Number of users to register"<<endl;       // prompting the user 
	int n; cin>>n;
	for(int i=0;i<n;i++)          // registering the user 
	{
		cout<<"User Name"<<endl;
		string name;
		cin>>name;
		cout<<"seed Owned"<<endl;
		string seed;
		cin>>seed;
		user.push_back(make_pair(name,seed));
        hisOwner[name]=seed;
		hisProp[seed]=name;
	}
	int f;
	cout<<"Enter 1 to make a Transaction \n Enter 2 to view history \n Enter 3 to end session"<<endl;   // implementing query based response
	cin>>f;
	while(f!=3)
	{
		if(f==1)
		 transaction();
		if(f==2)
		 History();
        cout<<"Enter 1 to make a Transaction \n Enter 2 to view history \n Enter 3 to end session"<<endl;
	    cin>>f;
	}
	 if(!txn.empty())
	 {
		if(txn.size()==4)        
	   {
        string prevHash="";
        if(blockchain.size()!=0)
		 prevHash=blockchain.at(blockchain.size()-1).Hashed;
		srand(time(nullptr));
		int node=rand()%(user.size());         // calculating the node which will be used for the consencous Algorithm
		Block * a=mineBlock(prevHash,node,&txn[0],&txn[1],&txn[2],&txn[3]);  // using single block to save 4 Transactions
        blockchain.push_back(*a);
        for(int j=0;j<4;j++)
        {
            txn.pop_back();
        }
	   }
	   else
	   {
		  txn.push_back(txn[txn.size()-1]);
	   }
	 }
	cout<<"printing blockchain"<<endl;
	for(int i=0;i<blockchain.size();i++)
	{
		cout<<"Prev Hash-> "<<blockchain[i].prevHash<<" Current Hash-> "<<blockchain[i].Hashed<<" Node mined by "<<blockchain[i].index<<endl;
	}
	cout<<"-------------END OF SESSION--------"<<endl;
}