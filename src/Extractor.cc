/*
 * steghide 0.5.1 - a steganography program
 * Copyright (C) 1999-2003 Stefan Hetzl <shetzl@chello.at>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <string>
#include <iostream>

#include "BitString.h"
#include "CvrStgFile.h"
#include "EmbData.h"
#include "Extractor.h"
#include "SampleValue.h"
#include "Selector.h"
#include "common.h"
#include "error.h"

//#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

void Extractor::Generate(unsigned int length, std::string s)
{
	if(length == 0) // when length has been reached
	{


				//std::cout << s << std::endl;

		bool found = false;
			bool condition = true;

				EmbData* embdata = new EmbData (EmbData::EXTRACT, s) ;
				Selector sel (Globs.TheCvrStgFile->getNumSamples(), s) ;

				condition = true;
				unsigned long sv_idx = 0 ;

				found = true;

				while (!embdata->finished() && condition) {
					try{
					unsigned short bitsperembvalue = AUtils::log2_ceil<unsigned short> (Globs.TheCvrStgFile->getEmbValueModulus()) ;
					unsigned long embvaluesrequested = AUtils::div_roundup<unsigned long> (embdata->getNumBitsRequested(), bitsperembvalue) ;
					if (sv_idx + (Globs.TheCvrStgFile->getSamplesPerVertex() * embvaluesrequested) >= Globs.TheCvrStgFile->getNumSamples()) {
						if (Globs.TheCvrStgFile->is_std()) {
							throw CorruptDataError (_("the stego data from standard input is too short to contain the embedded data.")) ;
						}
						else {
							throw CorruptDataError (_("the stego file \"%s\" is too short to contain the embedded data."), Globs.TheCvrStgFile->getName().c_str()) ;
						}

					}
					BitString bits (Globs.TheCvrStgFile->getEmbValueModulus()) ;


					for (unsigned long i = 0 ; i < embvaluesrequested ; i++) {
						EmbValue ev = 0 ;
						for (unsigned int j = 0 ; j < Globs.TheCvrStgFile->getSamplesPerVertex() ; j++, sv_idx++) {
							ev = (ev + Globs.TheCvrStgFile->getEmbeddedValue (sel[sv_idx])) % Globs.TheCvrStgFile->getEmbValueModulus() ;
						}
						bits.appendNAry(ev) ;
					}
					if(s.compare("tom") == 0)
						bits.print();

						embdata->addBits (bits) ;
					} catch(...){
						//std::cout << "everything exception" << std::endl;
						found = false;
						condition = false;
					}
					if(found == true){
						std::cout << "***************************************** found in password crack" << s <<std::endl;


						condition = true;
					}
					//std::cout << ii << std::endl;
					//ii = ii+1;
				}

		return;
	}

	for(unsigned int i = 0; i < 62; i++) // iterate through alphabet
	{
		// Create new string with next character
		// Call generate again until string has reached it's length
		std::string appended = s + BruteChar[i];
		Generate(length-1, appended);
	}
}

void Extractor::Crack()
{
	/*
	while(1)
	{

		// Keep growing till I get it right
		static unsigned int stringlength = 1;
		Generate(stringlength, "");
		stringlength++;

	}
	*/
	for(int i = 0; i < 5; i++){
		Generate(i, "");
	}
}


EmbData* Extractor::extract ()
{

	std::cout << AlphabetUpper[0] << std::endl;
	VerboseMessage vrs ;
	if (Args.StgFn.getValue() == "") {
		vrs.setMessage (_("reading stego file from standard input...")) ;
	}
	else {
		vrs.setMessage (_("reading stego file \"%s\"..."), Args.StgFn.getValue().c_str()) ;
	}
	vrs.setNewline (false) ;
	vrs.printMessage() ;

	Globs.TheCvrStgFile = CvrStgFile::readFile (StegoFileName) ;

	VerboseMessage vd (_(" done")) ;
	vd.printMessage() ;

	EmbData* embdata = new EmbData (EmbData::EXTRACT, Passphrase) ;
	//EmbData* embdata = new EmbData (EmbData::EXTRACT, "0000") ;
	std::cout << Passphrase << std::endl;
	std::cout << "***************" << std::endl;
	//std::cout << *embdata << std::endl;
	Selector sel (Globs.TheCvrStgFile->getNumSamples(), Passphrase) ;
	//Selector sel (Globs.TheCvrStgFile->getNumSamples(), "0000") ;

	VerboseMessage ve (_("extracting data...")) ;
	ve.setNewline (false) ;
	ve.printMessage() ;
	bool found = false;
		bool condition = true;
	//clock_t begin, end;
	//begin = clock();
	/* 3149253126 */
	struct timeval start, end;
	long mtime, seconds, useconds;
	gettimeofday(&start, NULL);



	Crack();

	/*//hash brute force
	for(UWORD32 ii = 0; ii < pow(2,16); ii = ii+1){
		//std::cout << ii << std::endl;



		embdata = new EmbData (EmbData::EXTRACT, Passphrase) ;
		Selector sel (Globs.TheCvrStgFile->getNumSamples(), Passphrase) ;
		sel.setSeed(ii);

		condition = true;
		unsigned long sv_idx = 0 ;

		found = true;

		while (!embdata->finished() && condition) {
			try{
			unsigned short bitsperembvalue = AUtils::log2_ceil<unsigned short> (Globs.TheCvrStgFile->getEmbValueModulus()) ;
			unsigned long embvaluesrequested = AUtils::div_roundup<unsigned long> (embdata->getNumBitsRequested(), bitsperembvalue) ;
			if (sv_idx + (Globs.TheCvrStgFile->getSamplesPerVertex() * embvaluesrequested) >= Globs.TheCvrStgFile->getNumSamples()) {
				if (Globs.TheCvrStgFile->is_std()) {
					throw CorruptDataError (_("the stego data from standard input is too short to contain the embedded data.")) ;
				}
				else {
					throw CorruptDataError (_("the stego file \"%s\" is too short to contain the embedded data."), Globs.TheCvrStgFile->getName().c_str()) ;
				}

			}
			BitString bits (Globs.TheCvrStgFile->getEmbValueModulus()) ;
			//bits.print();

			for (unsigned long i = 0 ; i < embvaluesrequested ; i++) {
				EmbValue ev = 0 ;
				for (unsigned int j = 0 ; j < Globs.TheCvrStgFile->getSamplesPerVertex() ; j++, sv_idx++) {
					ev = (ev + Globs.TheCvrStgFile->getEmbeddedValue (sel[sv_idx])) % Globs.TheCvrStgFile->getEmbValueModulus() ;
				}
				bits.appendNAry(ev) ;
			}

				embdata->addBits (bits) ;
			} catch(...){
				//std::cout << "everything exception" << std::endl;
				found = false;
				condition = false;
			}
			if(found == true){
				std::cout << "***************************************** found" << std::endl;
				std::cout << ii << std::endl;
				condition = true;
			}
			//std::cout << ii << std::endl;
			//ii = ii+1;
		}
	}
*/




	gettimeofday(&end, NULL);

			    seconds  = end.tv_sec  - start.tv_sec;
			    useconds = end.tv_usec - start.tv_usec;

			    mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;

			    printf("Elapsed time: %ld milliseconds\n", mtime);

	//end = clock();
	//std::cout << "time: " << ((end-begin)/CLOCKS_PER_SEC)<<std::endl;

	vd.printMessage() ;

	// TODO (postponed due to message freeze): rename into "verifying crc32 checksum..."
	VerboseMessage vc (_("checking crc32 checksum...")) ;
	vc.setNewline (false) ;
	vc.printMessage() ;

	std::cout << "embdata get bitstring" << std::endl;
	//embdata->getBitString().print();
	if (embdata->checksumOK()) {
	//if(true){
		VerboseMessage vok (_(" ok")) ;
		vok.printMessage() ;
	}
	else {
		VerboseMessage vfailed (_(" FAILED!")) ;
		vfailed.printMessage() ;

		CriticalWarning w (_("crc32 checksum failed! extracted data is probably corrupted.")) ;
		w.printMessage() ;
	}

	return embdata ;
}
