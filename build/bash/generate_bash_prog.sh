_generate_compile_bash_prog() {
	
	"$scriptAbsoluteLocation" _compile_bash rOverrides.sh 
	
	return
	# Legacy code below, kept for reference 
		
	"$scriptAbsoluteLocation" _true	 		# If no compiles are needed, this must be called before return 
	
	rm "$scriptAbsoluteFolder"/ubiquitous_bash.sh
	
	#"$scriptAbsoluteLocation" _compile_bash cautossh cautossh
	#"$scriptAbsoluteLocation" _compile_bash lean lean.sh
	
	"$scriptAbsoluteLocation" _compile_bash core ubiquitous_bash.sh
	
	#"$scriptAbsoluteLocation" _compile_bash "" ""
	#"$scriptAbsoluteLocation" _compile_bash ubiquitous_bash ubiquitous_bash.sh
	
	#"$scriptAbsoluteLocation" _package
}
