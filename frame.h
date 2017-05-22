#ifndef	_FRAME_H_
#define	_FRAME_H_

// cmds
enum cmd_type {
	cmdSYN  = 0, 		// stream open
	cmdFIN,             // stream close, a.k.a EOF mark
	cmdPSH,             // data push
	cmdNOP,             // no operation
};

// const (
// 	sizeOfVer    = 1
// 	sizeOfCmd    = 1
// 	sizeOfLength = 2
// 	sizeOfSid    = 4
// 	headerSize   = sizeOfVer + sizeOfCmd + sizeOfSid + sizeOfLength
// )

#endif //_FRAME_H_